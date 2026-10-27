package activatekey

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/handler/common"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/orchestrator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

const (
	TaskType     = "activate-key"
	retryBackoff = 30 * time.Second
)

var (
	ErrTaskFailed         = errors.New("task failed")
	ErrKeyVersionNotFound = errors.New("key version not found")
)

type TaskHandler struct {
	transactor store.Transactor
	rootName   string
	registry   *grpcconn.Registry
	manager    *keyprocessor.Manager
	config     *config.RootConfig
}

var _ orchestrator.TaskHandler = &TaskHandler{}

func NewTaskHandler(
	transactor store.Transactor,
	registry *grpcconn.Registry,
	rootName string,
	manager *keyprocessor.Manager,
	cfg *config.RootConfig,
) *TaskHandler {
	return &TaskHandler{
		transactor: transactor,
		rootName:   rootName,
		registry:   registry,
		manager:    manager,
		config:     cfg,
	}
}

// TaskType implements [orchestrator.TaskHandler].
func (h *TaskHandler) TaskType() string {
	return TaskType
}

// Handle implements [orchestrator.TaskHandler].
func (h *TaskHandler) Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	var kid handler.KeyIdentifier

	err := json.Unmarshal(req.TaskData, &kid)
	if err != nil {
		_ = markFail(resp, fmt.Sprintf("failed to unmarshal task data: %v", err))
		return
	}

	err = store.ChainTransaction(ctx, h.transactor,
		common.ValidateTenantID(kid.TenantID),
		common.EnsureKey(kid, func(key *model.Key) bool {
			return key.LifeCycleState == model.KeyLifeCycleActive &&
				key.KeyProcessingState.Status == model.KeyProcessingPending
		}),
		func(ctx context.Context, stores store.Stores) error {
			proc := common.NewProcessor(
				h.rootName,
				h.manager,
				h.config,
				h.registry,
				stores,
			)

			or := proc.ResolveKeyAndVersions(ctx, kid)
			if or != nil {
				return or.Apply(resp)
			}

			or = proc.GenerateAndSealSecret(ctx)
			if or != nil {
				return or.Apply(resp)
			}

			or = proc.UpsertRemote(ctx)
			if or != nil {
				return or.Apply(resp)
			}

			or = proc.MarkKeyComplete(ctx)
			if or != nil {
				return or.Apply(resp)
			}

			return markComplete(resp)
		},
	)
	if err != nil {
		slog.Error("failed to activate key", "error", err, "key_id", kid.ID, "tenant_id", kid.TenantID)
		if r, ok := errors.AsType[*common.OrbitalResponseError](err); ok {
			_ = r.Apply(resp)
			return
		}
		resp.ContinueAndWaitFor(retryBackoff)
	}
}

func fetchAndUpsertExistingKeyVersion(ctx context.Context, stores store.Stores, key model.Key) (*model.KeyVersion, error) {
	kvStore := stores.KeyVersions
	// check if keyversion is already present
	kvList, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
		TenantID: key.TenantID,
		KeyID:    key.ID,
		OrderBy: []store.KeyVersionOrder{
			store.KeyVersionOrderVersionDesc,
			store.KeyVersionOrderRevisionDesc,
		},
		Limit: 1,
	})
	if err != nil {
		return nil, err
	}
	if len(kvList.KeyVersions) == 0 {
		return nil, ErrKeyVersionNotFound
	}

	kv := kvList.KeyVersions[0]
	err = kvStore.UpdateKeyVersionStates(ctx, store.UpdateKeyVersionStatesQuery{
		TenantID:            kv.TenantID,
		KeyID:               kv.KeyID,
		Version:             kv.Version,
		Revision:            kv.Revision,
		FromProcessingState: []model.KeyVersionProcessingState{kv.ProcessingState},
		ToProcessingState:   model.KeyVersionUsable,
		FromLifeCycleState:  []model.KeyLifeCycleState{kv.LifeCycleState},
		ToLifeCycleState:    model.KeyLifeCycleActive,
	})
	if err != nil {
		return nil, err
	}
	kv.LifeCycleState = model.KeyLifeCycleActive
	kv.ProcessingState = model.KeyVersionUsable
	return &kv, nil
}

func createAndUpsertKeyVersionFromParent(ctx context.Context, stores store.Stores, key model.Key) (*model.KeyVersion, error) {
	kvStore := stores.KeyVersions

	var parentKeyVersion *int
	if key.ParentID != nil {
		// if not there we need to create a new keyversion based on the parent keyversion
		pkv, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        key.TenantID,
			KeyID:           *key.ParentID,
			ProcessingState: model.KeyVersionUsable,
			LifeCycleState:  model.KeyLifeCycleActive,
			OrderBy: []store.KeyVersionOrder{
				store.KeyVersionOrderVersionDesc,
				store.KeyVersionOrderRevisionDesc,
			},
			Limit: 1,
		})
		if err != nil {
			return nil, err
		}
		if len(pkv.KeyVersions) == 0 {
			return nil, fmt.Errorf("%w: parent key version not found for key %s", ErrTaskFailed, key.ID)
		}
		parentKeyVersion = new(pkv.KeyVersions[0].Version)
	}

	kv := model.NewKeyVersion(key.TenantID, key.ID, 1, key.ParentID, parentKeyVersion)
	kv.LifeCycleState = model.KeyLifeCycleActive
	kv.ProcessingState = model.KeyVersionUsable

	kvres, err := kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{
		KeyVersion: kv,
	})
	if err != nil {
		return nil, err
	}

	return &kvres.KeyVersion, nil
}

func markFail(resp *orbital.HandlerResponse, msg string) error {
	resp.Fail(msg)
	return nil
}

func markComplete(resp *orbital.HandlerResponse) error {
	resp.Complete()
	return nil
}
