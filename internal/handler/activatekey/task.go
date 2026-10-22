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
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/orchestrator"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keyversions"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
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
	config     config.RootConfig
}

var _ orchestrator.TaskHandler = &TaskHandler{}

func NewTaskHandler(
	transactor store.Transactor,
	registry *grpcconn.Registry,
	rootName string,
	manager *keyprocessor.Manager,
	cfg config.RootConfig,
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
	var id handler.KeyIdentifier

	err := json.Unmarshal(req.TaskData, &id)
	if err != nil {
		_ = markFail(resp, fmt.Sprintf("failed to unmarshal task data: %v", err))
		return
	}

	err = h.transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
		// fetching the key to make sure it exists and is in the correct state
		key, err := stores.Keys.GetKeyByID(ctx, id.ID, id.TenantID)
		if err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				return markFail(resp, fmt.Sprintf("key not found: %v", err))
			}
			return markContinue(resp, err)
		}

		// defensive check, this should not happen, but if it does, we will mark the task as failed
		if key == nil {
			return markFail(resp, "key not found")
		}

		// making sure that no other process has already changed the status of the key,
		// if so, we will mark the task as complete and not retry
		isKeyTaken := key.LifeCycleState != model.KeyLifeCycleActive ||
			key.KeyProcessingState.Status != model.KeyProcessingPending

		if isKeyTaken {
			return markComplete(resp)
		}

		tenantID, managedBy := key.TenantID, key.ManagedBy

		// check tenant status
		err = validator.ValidateTenant(tenantID)(ctx, stores)
		if err != nil {
			return markContinue(resp, err)
		}

		// get the key version, if it exists, we will upsert it to the remote agent, if not,
		// we will create a new key version based on the parent key version
		kv, isNewKV, err := upsertAndResolveKeyVersion(ctx, stores, *key)
		if err != nil {
			if errors.Is(err, ErrTaskFailed) {
				return markKeyFailed(ctx, resp, stores, *key, "parent key version is not in usable state, cannot create new key version")
			}
			return markContinue(resp, err)
		}

		// defensive check, this should not happen, but if it does, we will mark the task as failed
		if kv == nil {
			return markFail(resp, "keyversion not found")
		}

		// check if key is root key
		isRootKey, err := isValidRootKeyKind(*key, h.config)
		if err != nil {
			if errors.Is(err, ErrTaskFailed) {
				return markKeyFailed(ctx, resp, stores, *key, fmt.Sprintf("failed to determine if key is root: %v", err))
			}
			return markContinue(resp, err)
		}

		isManagedByRoot := key.ManagedBy == h.rootName

		// check if the key is managed by root and is not a root key, if so, we need to generate and seal the secret for this key version
		if isManagedByRoot && !isRootKey && isNewKV {
			err := generateAndSealSecret(ctx, h.manager, *key, *kv)
			if err != nil {
				return markContinue(resp, err)
			}
		}

		// if the key is managed by a remote agent, we need to upsert the key version to the remote agent
		if !isManagedByRoot {
			err = upsertRemoteKeyVersion(ctx, h.registry, managedBy, *kv)
			if err != nil {
				if errors.Is(err, ErrTaskFailed) {
					return markKeyFailed(ctx, resp, stores, *key, err.Error())
				}
				return markContinue(resp, err)
			}
		}

		// here the state of the key is updated from pending to completed
		err = markKeyAsActiveAndComplete(ctx, stores, *key)
		if err != nil {
			return markContinue(resp, fmt.Errorf("failed to update key state to completed: %w", err))
		}

		return markComplete(resp)
	})
	if err != nil {
		slog.Error("failed to activate key", "error", err, "key_id", id.ID, "tenant_id", id.TenantID)
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

func upsertRemoteKeyVersion(ctx context.Context, reg *grpcconn.Registry, managedBy string, kv model.KeyVersion) error {
	if reg == nil {
		return fmt.Errorf("%w: registry is nil, cannot upsert key version", ErrTaskFailed)
	}

	conn, ok := reg.Get(managedBy)
	if !ok {
		return fmt.Errorf("%w: no connection found for agent "+managedBy, ErrTaskFailed)
	}

	var parentKeyID string
	if kv.ParentKeyID != nil {
		parentKeyID = *kv.ParentKeyID
	}
	var parentKeyVersion int32
	if kv.ParentKeyVersion != nil {
		parentKeyVersion = int32(*kv.ParentKeyVersion)
	}

	_, err := keyversions.NewKeyVersionServiceClient(conn).
		UpsertKeyVersion(ctx, &keyversions.UpsertKeyVersionRequest{
			TenantId:        kv.TenantID,
			KeyId:           kv.KeyID,
			Version:         int32(kv.Version),
			Revision:        int32(kv.Revision),
			ParentId:        parentKeyID,
			ParentVersion:   parentKeyVersion,
			LifecycleState:  string(kv.LifeCycleState),
			ProcessingState: string(kv.ProcessingState),
		})
	if err == nil {
		return nil
	}

	if proto.Retryable(err) {
		return err
	}
	return fmt.Errorf("%w: failed to upsert key version to remote agent %s: %w", ErrTaskFailed, managedBy, err)
}

func isValidRootKeyKind(key model.Key, cfg config.RootConfig) (bool, error) {
	s, ok := cfg.Hierarchy.FindKeySpec(key.Kind)
	if !ok {
		return false, fmt.Errorf("%w: key kind %s not found in hierarchy", ErrTaskFailed, key.Kind)
	}

	return s.Role == spec.KeyRoleRoot, nil
}

func upsertAndResolveKeyVersion(ctx context.Context, stores store.Stores, key model.Key) (*model.KeyVersion, bool, error) {
	var isNew bool
	kv, err := fetchAndUpsertExistingKeyVersion(ctx, stores, key)
	if err != nil {
		if !errors.Is(err, ErrKeyVersionNotFound) {
			return nil, isNew, err
		}
		kv, err = createAndUpsertKeyVersionFromParent(ctx, stores, key)
		if err != nil {
			return nil, isNew, err
		}
		isNew = true
	}
	return kv, isNew, nil
}

func generateAndSealSecret(ctx context.Context, manager *keyprocessor.Manager, key model.Key, kv model.KeyVersion) error {
	aad := fmt.Appendf(nil, "%s:%s:%d:%d:%d", key.TenantID, key.ID, kv.Version, kv.Revision, kv.CreatedAt)
	_, err := manager.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
		KeyVersion: kv,
		AAD:        aad,
		KeyKind:    key.Kind,
	})
	return err
}

func markKeyAsActiveAndComplete(ctx context.Context, stores store.Stores, key model.Key) error {
	err := stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
		ID:         key.ID,
		TenantID:   key.TenantID,
		FromState:  []model.KeyLifeCycleState{model.KeyLifeCycleActive},
		ToState:    model.KeyLifeCycleActive,
		FromStatus: []model.KeyProcessingStatus{model.KeyProcessingPending},
		ToStatus:   model.KeyProcessingCompleted,
	})
	return err
}

func markFail(resp *orbital.HandlerResponse, msg string) error {
	resp.Fail(msg)
	return nil
}

func markKeyFailed(ctx context.Context, resp *orbital.HandlerResponse, stores store.Stores, key model.Key, msg string) error {
	err := stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
		ID:         key.ID,
		TenantID:   key.TenantID,
		FromState:  []model.KeyLifeCycleState{key.LifeCycleState},
		ToState:    key.LifeCycleState,
		FromStatus: []model.KeyProcessingStatus{key.KeyProcessingState.Status},
		ToStatus:   model.KeyProcessingFailed,
	})
	if err != nil {
		resp.ContinueAndWaitFor(retryBackoff)
		return err
	}
	// this error should not happen, but if it does, we will retry the task
	resp.Fail(msg)
	return nil
}

func markContinue(resp *orbital.HandlerResponse, err error) error {
	resp.ContinueAndWaitFor(retryBackoff)
	return err
}

func markComplete(resp *orbital.HandlerResponse) error {
	resp.Complete()
	return nil
}
