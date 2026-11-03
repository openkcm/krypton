package orchestrator

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
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/tenants"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

const retryBackoff = 2 * time.Second

// AnnounceTaskHandler is the [OrbitalTaskHandler] for the announce-key task type.
// It validates the tenant, upserts the tenant and key to the remote agent,
// and updates the key's processing state.
type AnnounceTaskHandler struct {
	transactor store.Transactor
	registry   *grpcconn.Registry
	rootName   string
}

var _ OrbitalTaskHandler = &AnnounceTaskHandler{}

func NewAnnounceTaskHandler(transactor store.Transactor, registry *grpcconn.Registry, rootName string) *AnnounceTaskHandler {
	return &AnnounceTaskHandler{
		transactor: transactor,
		registry:   registry,
		rootName:   rootName,
	}
}

func (h *AnnounceTaskHandler) TaskType() string {
	return AnnounceKey
}

func (h *AnnounceTaskHandler) Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	var key model.Key
	if err := json.Unmarshal(req.TaskData, &key); err != nil {
		resp.Fail(fmt.Sprintf("unmarshal task data: %v", err))
		return
	}

	state := newAnnounceState()

	err := store.ChainTransaction(ctx, h.transactor,
		func(ctx context.Context, stores store.Stores) error {
			return h.validateTenant(ctx, state, stores, key)
		},
		func(ctx context.Context, stores store.Stores) error {
			return h.upsertTenant(ctx, state, stores, key)
		},
		validator.ValidateTransition(key.TenantID, key.ID, model.KeyLifeCyclePreActivation),
		func(ctx context.Context, _ store.Stores) error {
			return h.upsertKey(ctx, state, &key)
		},
		func(ctx context.Context, stores store.Stores) error {
			return h.updateKeyState(ctx, state, stores, key)
		},
	)

	switch {
	case err != nil && !isTerminalTxErr(err):
		resp.ContinueAndWaitFor(retryBackoff)
	case err != nil:
		resp.Fail(err.Error())
	case state.state == model.KeyProcessingFailed:
		resp.Fail(state.errMsg)
	default:
		resp.Complete()
	}
}

func (h *AnnounceTaskHandler) validateTenant(ctx context.Context, sharedState *announceState, stores store.Stores, key model.Key) error {
	err := validator.ValidateTenant(key.TenantID)(ctx, stores)
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			sharedState.withState(model.KeyProcessingFailed).
				withErrorMessage(fmt.Sprintf("tenant %q not found", key.TenantID))
			return nil
		}
		return err
	}
	return nil
}

func (h *AnnounceTaskHandler) updateKeyState(ctx context.Context, sharedState *announceState, stores store.Stores, key model.Key) error {
	if sharedState.state == "" {
		sharedState.withState(model.KeyProcessingFailed).
			withErrorMessage("internal error: state not set before updating key state")
	}

	return keyoperator.UpdateKeyState(key.TenantID, key.ID, keyoperator.Transition{
		FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
		ToLifeCycle:    model.KeyLifeCyclePreActivation,
		FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingInProgress},
		ToProcessing:   sharedState.state,
	})(ctx, stores)
}

func (h *AnnounceTaskHandler) upsertTenant(ctx context.Context, sharedState *announceState, stores store.Stores, key model.Key) error {
	if sharedState.isTerminalState() {
		return nil
	}

	t, err := stores.Tenants.GetTenant(ctx, store.GetTenantQuery{
		ID: key.TenantID,
	})
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			sharedState.withState(model.KeyProcessingFailed).
				withErrorMessage(fmt.Sprintf("tenant %q not found", key.TenantID))
			return nil
		}
		return err
	}

	if key.ManagedBy == h.rootName {
		return nil
	}

	c, ok := h.registry.Get(key.ManagedBy)
	if !ok {
		sharedState.withState(model.KeyProcessingFailed).
			withErrorMessage(fmt.Sprintf("no connection registered for target %q", key.ManagedBy))
		return nil
	}

	_, err = tenants.NewTenantServiceClient(c).UpsertTenant(ctx, &tenants.UpsertTenantRequest{
		Id:     t.Tenant.ID,
		Name:   t.Tenant.Name,
		Labels: t.Tenant.Labels,
	})
	if err != nil {
		if !isTerminalUpsertErr(err) {
			return err
		}
		sharedState.withState(model.KeyProcessingFailed).
			withErrorMessage(fmt.Sprintf("upsert rejected by agent %q: %v", key.ManagedBy, err))
		return nil
	}

	return nil
}

func (h *AnnounceTaskHandler) upsertKey(ctx context.Context, sharedState *announceState, key *model.Key) error {
	if sharedState.isTerminalState() {
		return nil
	}

	if key.ManagedBy == h.rootName {
		sharedState.withState(model.KeyProcessingCompleted)
		return nil
	}

	c, ok := h.registry.Get(key.ManagedBy)
	if !ok {
		sharedState.withState(model.KeyProcessingFailed).
			withErrorMessage(fmt.Sprintf("no connection registered for target %q", key.ManagedBy))
		return nil
	}

	_, err := keys.NewKeyServiceClient(c).UpsertKey(ctx, toUpsertRequest(key))
	if err != nil {
		if !isTerminalUpsertErr(err) {
			return err
		}

		sharedState.withState(model.KeyProcessingFailed).
			withErrorMessage(fmt.Sprintf("upsert rejected by agent %q: %v", key.ManagedBy, err))
		return nil
	}

	sharedState.withState(model.KeyProcessingCompleted)
	return nil
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
