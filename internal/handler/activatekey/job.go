package activatekey

import (
	"context"
	"encoding/json/v2"
	"fmt"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/orchestrator"
)

// JobType is the orbital job type for key activation.
const JobType = "activate-key"

// JobHandler handles the orbital job lifecycle for activating keys.
// It unmarshals a [handler.KeyLayer] from the job payload and fans out
// one task per key identifier to the local operator target.
type JobHandler struct {
	localTarget string
}

var _ orchestrator.JobHandler = &JobHandler{}

// NewJobHandler returns a JobHandler that routes tasks to localTarget.
func NewJobHandler(localTarget string) *JobHandler {
	return &JobHandler{
		localTarget: localTarget,
	}
}

func (h *JobHandler) JobType() string {
	return JobType
}

// ResolveTasks decodes the job's [handler.KeyLayer] payload and creates one
// activate-key task per key identifier. The job is canceled when the payload
// is invalid or contains no identifiers.
func (h *JobHandler) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	var layer handler.KeyLayer
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
			Type:   TaskType,
			Target: h.localTarget,
		})
	}

	return orbital.CompleteTaskResolver().WithTaskInfo(infos), nil
}

// ConfirmJob unconditionally approves the job; activate-key has no
// precondition to verify.
func (h *JobHandler) ConfirmJob(_ context.Context, _ orbital.Job) (orbital.JobConfirmerResult, error) {
	return orbital.CompleteJobConfirmer(), nil
}

func (h *JobHandler) OnJobCanceled(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "activate-key layer canceled", "jobID", job.ID)
	return nil
}

func (h *JobHandler) OnJobDone(ctx context.Context, job orbital.Job) error {
	slogctx.Info(ctx, "activate-key layer completed", "jobID", job.ID)
	return nil
}

func (h *JobHandler) OnJobFailed(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "activate-key layer failed", "jobID", job.ID, "error", job.ErrorMessage)
	return nil
}
