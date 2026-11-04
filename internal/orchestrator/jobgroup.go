package orchestrator

import (
	"context"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"
)

// JobGroupHandler is a [OrbitalJobGroupHandler] that logs terminal events
// for key-processing job groups.
type JobGroupHandler struct {
	cfg HandlerConfig
}

var _ OrbitalJobGroupHandler = &JobGroupHandler{}

func NewJobGroupHandler(cfg HandlerConfig) *JobGroupHandler {
	return &JobGroupHandler{cfg: cfg}
}

func (h *JobGroupHandler) JobGroupType() string {
	return h.cfg.handlerType
}

func (h *JobGroupHandler) OnJobGroupDone(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Info(ctx, "job group done", "handler", h.cfg, "jobGroupID", group.ID)
	return nil
}

func (h *JobGroupHandler) OnJobGroupFailed(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Warn(ctx, "job group failed", "handler", h.cfg, "jobGroupID", group.ID, "error", group.ErrorMessage)
	return nil
}

func (h *JobGroupHandler) OnJobGroupCanceled(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Warn(ctx, "job group canceled", "handler", h.cfg, "jobGroupID", group.ID)
	return nil
}
