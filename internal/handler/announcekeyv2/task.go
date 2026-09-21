package announcekeyv2

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/internal/orchestrator"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

const TaskType = "announce-key"

const retryBackoff = 2 * time.Second

type TaskHandler struct {
	transactor store.Transactor
	registry   *grpcconn.Registry
	rootName   string
}

var _ orchestrator.TaskHandler = &TaskHandler{}

func NewTaskHandler(transactor store.Transactor, registry *grpcconn.Registry, rootName string) *TaskHandler {
	return &TaskHandler{
		transactor: transactor,
		registry:   registry,
		rootName:   rootName,
	}
}

func (h *TaskHandler) TaskType() string {
	return TaskType
}

type result struct {
	procState model.KeyProcessingStatus
	failMsg   string
}

func (h *TaskHandler) Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	var key model.Key
	if err := json.Unmarshal(req.TaskData, &key); err != nil {
		resp.Fail(fmt.Sprintf("unmarshal task data: %v", err))
		return
	}

	var result result
	err := store.ChainTransaction(ctx, h.transactor,
		validator.ValidateTransition(key.TenantID, key.ID, model.KeyLifeCyclePreActivation),
		func(ctx context.Context, _ store.Stores) error {
			r, err := h.upsertKey(ctx, &key)
			result = r
			return err
		},
		keyoperator.UpdateKeyState(key.TenantID, key.ID, keyoperator.Transition{
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
			ToLifeCycle:    model.KeyLifeCyclePreActivation,
			FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingInProgress},
			ToProcessing:   result.procState,
		}),
	)

	switch {
	case err != nil && !isTerminalTxErr(err):
		resp.ContinueAndWaitFor(retryBackoff)
	case err != nil:
		resp.Fail(err.Error())
	case result.procState == model.KeyProcessingFailed:
		resp.Fail(result.failMsg)
	default:
		resp.Complete()
	}
}

func (h *TaskHandler) upsertKey(ctx context.Context, key *model.Key) (result, error) {
	if key.ManagedBy == h.rootName {
		return result{procState: model.KeyProcessingCompleted}, nil
	}

	conn, ok := h.registry.Get(key.ManagedBy)
	if !ok {
		return result{
			procState: model.KeyProcessingFailed,
			failMsg:   fmt.Sprintf("no connection registered for target %q", key.ManagedBy),
		}, nil
	}

	_, err := keys.NewKeyServiceClient(conn).UpsertKey(ctx, toUpsertRequest(key))
	if err != nil {
		if !isTerminalUpsertErr(err) {
			return result{}, err
		}
		return result{
			procState: model.KeyProcessingFailed,
			failMsg:   fmt.Sprintf("upsert rejected by agent %q: %v", key.ManagedBy, err),
		}, nil
	}

	return result{procState: model.KeyProcessingCompleted}, nil
}

func toUpsertRequest(key *model.Key) *keys.UpsertKeyRequest {
	parentID := ""
	if key.ParentID != nil {
		parentID = *key.ParentID
	}
	return &keys.UpsertKeyRequest{
		TenantId:       key.TenantID,
		KeyId:          key.ID,
		Kind:           string(key.Kind),
		Name:           key.Name,
		ParentId:       parentID,
		LifecycleState: string(key.LifeCycleState),
		ManagedBy:      key.ManagedBy,
		Labels:         map[string]string(key.Labels),
	}
}

func isTerminalUpsertErr(err error) bool {
	switch status.Code(err) {
	case codes.InvalidArgument, codes.FailedPrecondition:
		return true
	default:
		return false
	}
}

func isTerminalTxErr(err error) bool {
	return errors.Is(err, keylifecycle.ErrInvalidKeyStateTransition) ||
		errors.Is(err, keyoperator.ErrKeyTransitionRejected) ||
		errors.Is(err, store.ErrKeyNotFound)
}
