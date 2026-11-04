package orchestrator

import (
	"context"
	"encoding/json/v2"
	"fmt"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"
)

// TaskResolver is a [OrbitalTaskResolver] that unpacks a [KeyLayer] from the
// job data and fans out one task per key identifier.
type TaskResolver struct {
	cfg HandlerConfig
}

var _ OrbitalTaskResolver = &TaskResolver{}

func NewTaskResolver(cfg HandlerConfig) *TaskResolver {
	return &TaskResolver{cfg: cfg}
}

func (h *TaskResolver) JobType() string {
	return h.cfg.handlerType
}

func (h *TaskResolver) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
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

func (h *TaskResolver) ConfirmJob(_ context.Context, _ orbital.Job) (orbital.JobConfirmerResult, error) {
	return orbital.CompleteJobConfirmer(), nil
}

func (h *TaskResolver) OnJobCanceled(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "job canceled", "handler", h.cfg, "jobID", job.ID)
	return nil
}

func (h *TaskResolver) OnJobDone(ctx context.Context, job orbital.Job) error {
	slogctx.Info(ctx, "job completed", "handler", h.cfg, "jobID", job.ID)
	return nil
}

func (h *TaskResolver) OnJobFailed(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "job failed", "handler", h.cfg, "jobID", job.ID, "error", job.ErrorMessage)
	return nil
}
