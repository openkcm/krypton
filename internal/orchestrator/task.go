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

// TaskHandler is a [OrbitalTaskHandler] that processes a single key within
// a transaction: it validates the tenant and key, resolves key versions,
// generates and seals secrets, upserts to remote agents, and marks the key
// complete.
type TaskHandler struct {
	cfg        HandlerConfig
	rootCfg    *config.RootConfig
	transactor store.Transactor
	registry   *grpcconn.Registry
	manager    *keyprocessor.Manager
}

var _ OrbitalTaskHandler = &TaskHandler{}

func NewTaskHandler(
	handlerCfg HandlerConfig,
	transactor store.Transactor,
	registry *grpcconn.Registry,
	manager *keyprocessor.Manager,
	rootCfg *config.RootConfig,
) *TaskHandler {
	return &TaskHandler{
		cfg:        handlerCfg,
		rootCfg:    rootCfg,
		transactor: transactor,
		registry:   registry,
		manager:    manager,
	}
}

// TaskType implements [OrbitalTaskHandler].
func (m *TaskHandler) TaskType() string {
	return m.cfg.handlerType
}

// Handle implements [OrbitalTaskHandler].
func (m *TaskHandler) Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	var kid KeyIdentifier

	err := json.Unmarshal(req.TaskData, &kid)
	if err != nil {
		resp.Fail(fmt.Sprintf("handler %v failed to unmarshal task data: %v", m.cfg, err))
		return
	}

	err = store.ChainTransaction(ctx, m.transactor,
		ValidateTenantID(kid.TenantID),
		EnsureKey(kid, func(key *model.Key) bool {
			return key.LifeCycleState == m.cfg.toState &&
				key.KeyProcessingState.Status == model.KeyProcessingPending
		}),
		func(ctx context.Context, stores store.Stores) error {
			o := NewKeyOperator(
				KeyOperatorConfig{
					Manager:    m.manager,
					RootConfig: m.rootCfg,
					Registry:   m.registry,
					Stores:     stores,
					KID:        &kid,
				})
			return o.Execute(ctx, m.cfg.operatorPipeline, resp)
		},
	)
	if err != nil {
		if r, ok := errors.AsType[*OrbitalOperatorError](err); ok {
			// not checking the error here because we want to propagate the error to orbital for retry
			_ = r.Apply(resp)
			return
		}
		slog.Error("task failed", "handler", m.cfg, "error", err, "key_id", kid.ID, "tenant_id", kid.TenantID)
		resp.ContinueAndWaitFor(RetryBackoff)
	}
}
