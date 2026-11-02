package orchestrator

import (
	"context"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"
)

// KeyProcessJobGroupHandler is a [JobGroupHandler] that logs terminal events
// for key-processing job groups.
type KeyProcessJobGroupHandler struct {
	cfg HandlerConfig
}

var _ JobGroupHandler = &KeyProcessJobGroupHandler{}

func NewKeyProcessJobGroupHandler(cfg HandlerConfig) *KeyProcessJobGroupHandler {
	return &KeyProcessJobGroupHandler{cfg: cfg}
}

func (h *KeyProcessJobGroupHandler) JobGroupType() string {
	return h.cfg.handlerType
}

func (h *KeyProcessJobGroupHandler) OnJobGroupDone(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Info(ctx, "job group done", "handler", h.cfg, "jobGroupID", group.ID)
	return nil
}

func (h *KeyProcessJobGroupHandler) OnJobGroupFailed(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Warn(ctx, "job group failed", "handler", h.cfg, "jobGroupID", group.ID, "error", group.ErrorMessage)
	return nil
}

func (h *KeyProcessJobGroupHandler) OnJobGroupCanceled(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Warn(ctx, "job group canceled", "handler", h.cfg, "jobGroupID", group.ID)
	return nil
}
