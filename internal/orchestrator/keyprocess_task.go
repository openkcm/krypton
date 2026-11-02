package orchestrator

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// KeyProcessTaskHandler is a [TaskHandler] that processes a single key within
// a transaction: it validates the tenant and key, resolves key versions,
// generates and seals secrets, upserts to remote agents, and marks the key
// complete.
type KeyProcessTaskHandler struct {
	handlerCfg HandlerConfig
	transactor store.Transactor
	registry   *grpcconn.Registry
	manager    *keyprocessor.Manager
	rootCfg    *config.RootConfig
}

var _ TaskHandler = &KeyProcessTaskHandler{}

func NewKeyProcessTaskHandler(
	handleCfg HandlerConfig,
	transactor store.Transactor,
	registry *grpcconn.Registry,
	manager *keyprocessor.Manager,
	rootCfg *config.RootConfig,
) *KeyProcessTaskHandler {
	return &KeyProcessTaskHandler{
		handlerCfg: handleCfg,
		transactor: transactor,
		registry:   registry,
		manager:    manager,
		rootCfg:    rootCfg,
	}
}

// TaskType implements [orchestrator.TaskHandler].
func (h *KeyProcessTaskHandler) TaskType() string {
	return h.handlerCfg.handlerType
}

// Handle implements [orchestrator.TaskHandler].
func (h *KeyProcessTaskHandler) Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	var kid KeyIdentifier

	err := json.Unmarshal(req.TaskData, &kid)
	if err != nil {
		resp.Fail(fmt.Sprintf("handler %v failed to unmarshal task data: %v", h.handlerCfg, err))
		return
	}

	err = store.ChainTransaction(ctx, h.transactor,
		ValidateTenantID(kid.TenantID),
		EnsureKey(kid, func(key *model.Key) bool {
			return key.LifeCycleState == h.handlerCfg.toState &&
				key.KeyProcessingState.Status == model.KeyProcessingPending
		}),
		func(ctx context.Context, stores store.Stores) error {
			proc := NewKeyProcessOperator(
				KeyProcessOperatorConfig{
					Manager:    h.manager,
					RootConfig: h.rootCfg,
					Registry:   h.registry,
					Stores:     stores,
				},
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
		if r, ok := errors.AsType[*OrbitalOperatorError](err); ok {
			// not checking the error here because we want to propagate the error to orbital for retry
			_ = r.Apply(resp)
			return
		}
		slog.Error("task failed", "handler", h.handlerCfg, "error", err, "key_id", kid.ID, "tenant_id", kid.TenantID)
		resp.ContinueAndWaitFor(RetryBackoff)
	}
}

func markComplete(resp *orbital.HandlerResponse) error {
	resp.Complete()
	return nil
}
