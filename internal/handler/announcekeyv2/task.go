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
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/tenants"
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

func (h *TaskHandler) Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	var key model.Key
	if err := json.Unmarshal(req.TaskData, &key); err != nil {
		resp.Fail(fmt.Sprintf("unmarshal task data: %v", err))
		return
	}

	res := newSharedResult()

	err := store.ChainTransaction(ctx, h.transactor,
		func(ctx context.Context, stores store.Stores) error {
			return h.agentConn(res, key.ManagedBy).err
		},
		func(ctx context.Context, stores store.Stores) error {
			return h.validateAndUpsertTenant(ctx, res, stores, key).err
		},
		validator.ValidateTransition(key.TenantID, key.ID, model.KeyLifeCyclePreActivation),
		func(ctx context.Context, _ store.Stores) error {
			return h.upsertKey(ctx, res, &key).err
		},
		func(ctx context.Context, stores store.Stores) error {
			return keyoperator.UpdateKeyState(key.TenantID, key.ID, keyoperator.Transition{
				FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
				ToLifeCycle:    model.KeyLifeCyclePreActivation,
				FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingInProgress},
				ToProcessing:   res.procState,
			})(ctx, stores)
		},
	)

	switch {
	case err != nil && !isTerminalTxErr(err):
		resp.ContinueAndWaitFor(retryBackoff)
	case err != nil:
		resp.Fail(err.Error())
	case res.procState == model.KeyProcessingFailed:
		resp.Fail(res.failMsg)
	default:
		resp.Complete()
	}
}

func (h *TaskHandler) validateAndUpsertTenant(ctx context.Context, result *sharedResult, stores store.Stores, key model.Key) *sharedResult {
	if result.isResulted() {
		return result
	}

	t, err := stores.Tenants.GetTenant(ctx, store.GetTenantQuery{
		ID: key.TenantID,
	})
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			return result.withProcState(model.KeyProcessingFailed).
				withFailMsg(fmt.Sprintf("tenant %q not found", key.TenantID))
		}
		return result.withError(err)
	}

	if key.ManagedBy == h.rootName {
		return result
	}

	if result.conn == nil {
		return result.withProcState(model.KeyProcessingFailed).
			withFailMsg(fmt.Sprintf("no connection registered for target %q", key.ManagedBy))
	}

	_, err = tenants.NewTenantServiceClient(result.conn).UpsertTenant(ctx, &tenants.UpsertTenantRequest{
		Id:     t.Tenant.ID,
		Name:   t.Tenant.Name,
		Labels: t.Tenant.Labels,
	})
	if err != nil {
		if !isTerminalUpsertErr(err) {
			return result.withError(err)
		}
		return result.withProcState(model.KeyProcessingFailed).
			withFailMsg(fmt.Sprintf("upsert rejected by agent %q: %v", key.ManagedBy, err))
	}

	return result
}

func (h *TaskHandler) agentConn(result *sharedResult, managedBy string) *sharedResult {
	if result.isResulted() {
		return result
	}

	if managedBy == h.rootName {
		return result
	}

	c, ok := h.registry.Get(managedBy)
	if !ok {
		return result.withProcState(model.KeyProcessingFailed).
			withFailMsg(fmt.Sprintf("no connection registered for target %q", managedBy))
	}

	return result.withConn(c)
}

func (h *TaskHandler) upsertKey(ctx context.Context, result *sharedResult, key *model.Key) *sharedResult {
	if result.isResulted() {
		return result
	}

	if key.ManagedBy == h.rootName {
		return result.withProcState(model.KeyProcessingCompleted)
	}

	if result.conn == nil {
		return result.withProcState(model.KeyProcessingFailed).
			withFailMsg(fmt.Sprintf("no connection registered for target %q", key.ManagedBy))
	}

	_, err := keys.NewKeyServiceClient(result.conn).UpsertKey(ctx, toUpsertRequest(key))
	if err != nil {
		if !isTerminalUpsertErr(err) {
			return result.withError(err)
		}

		return result.withProcState(model.KeyProcessingFailed).
			withFailMsg(fmt.Sprintf("upsert rejected by agent %q: %v", key.ManagedBy, err))
	}

	return result.withProcState(model.KeyProcessingCompleted)
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
