package activatekey

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"

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

const TaskType = "activate-key"

type TaskHandler struct {
	transactor store.Transactor
	registry   *grpcconn.Registry
	manager    *keyprocessor.Manager
	config     *config.RootConfig
}

var _ orchestrator.TaskHandler = &TaskHandler{}

func NewTaskHandler(
	transactor store.Transactor,
	registry *grpcconn.Registry,
	manager *keyprocessor.Manager,
	cfg *config.RootConfig,
) *TaskHandler {
	return &TaskHandler{
		transactor: transactor,
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
		resp.Fail(fmt.Sprintf("failed to unmarshal task data: %v", err))
		return
	}

	err = store.ChainTransaction(ctx, h.transactor,
		common.ValidateTenantID(kid.TenantID),
		common.EnsureKey(kid, func(key *model.Key) bool {
			return key.LifeCycleState == model.KeyLifeCycleActive &&
				key.KeyProcessingState.Status == model.KeyProcessingPending
		}),
		func(ctx context.Context, stores store.Stores) error {
			proc := common.NewOrbitalOperator(
				common.OrbitalOperatorConfig{
					Manager:    h.manager,
					RootConfig: h.config,
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
		if r, ok := errors.AsType[*common.OrbitalOperatorError](err); ok {
			// not checking the error here because we want to propagate the error to orbital for retry
			_ = r.Apply(resp)
			return
		}
		slog.Error("failed to activate key", "error", err, "key_id", kid.ID, "tenant_id", kid.TenantID)
		resp.ContinueAndWaitFor(common.RetryBackoff)
	}
}

func markComplete(resp *orbital.HandlerResponse) error {
	resp.Complete()
	return nil
}
