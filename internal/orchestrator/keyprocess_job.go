package orchestrator

import (
	"context"
	"encoding/json/v2"
	"fmt"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"
)

// KeyProcessJobHandler is a [JobHandler] that unpacks a [KeyLayer] from the
// job data and fans out one task per key identifier.
type KeyProcessJobHandler struct {
	cfg HandlerConfig
}

var _ JobHandler = &KeyProcessJobHandler{}

func NewKeyProcessJobHandler(cfg HandlerConfig) *KeyProcessJobHandler {
	return &KeyProcessJobHandler{cfg: cfg}
}

func (h *KeyProcessJobHandler) JobType() string {
	return h.cfg.handlerType
}

func (h *KeyProcessJobHandler) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	var layer KeyLayer
	if err := json.Unmarshal(job.Data, &layer); err != nil {
		return orbital.CancelTaskResolver(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	if len(layer.Identifiers) == 0 {
		return orbital.CancelTaskResolver("no key identifiers provided"), nil
	}

	infos := make([]orbital.TaskInfo, 0, len(layer.Identifiers))
	for _, id := range layer.Identifiers {
		infoData, err := json.Marshal(id)
		if err != nil {
			return orbital.CancelTaskResolver(fmt.Sprintf("marshal task data: %v", err)), nil
		}
		infos = append(infos, orbital.TaskInfo{
			Data:   infoData,
			Type:   h.cfg.handlerType,
			Target: DefaultLocalTargetName,
		})
	}

	return orbital.CompleteTaskResolver().WithTaskInfo(infos), nil
}

func (h *KeyProcessJobHandler) ConfirmJob(_ context.Context, _ orbital.Job) (orbital.JobConfirmerResult, error) {
	return orbital.CompleteJobConfirmer(), nil
}

func (h *KeyProcessJobHandler) OnJobCanceled(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "job canceled", "handler", h.cfg, "jobID", job.ID)
	return nil
}

func (h *KeyProcessJobHandler) OnJobDone(ctx context.Context, job orbital.Job) error {
	slogctx.Info(ctx, "job completed", "handler", h.cfg, "jobID", job.ID)
	return nil
}

func (h *KeyProcessJobHandler) OnJobFailed(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "job failed", "handler", h.cfg, "jobID", job.ID, "error", job.ErrorMessage)
	return nil
}
