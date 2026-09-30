package activatekey

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/pkg/store"
)

// JobHandler owns the orbital lifecycle for a single activation layer. It
// confirms the layer's keys exist and resolves the layer into one task per key,
// targeted at root's embedded operator.
type JobHandler struct {
	keyStore    store.Key
	localTarget string
}

// NewJobHandler builds the layer job handler. localTarget is the embedded
// operator's target name (orchestrator.LocalTarget()) so tasks run in-process
// on root.
func NewJobHandler(keyStore store.Key, localTarget string) *JobHandler {
	return &JobHandler{keyStore: keyStore, localTarget: localTarget}
}

func (h *JobHandler) JobType() string {
	return JobType
}

// ConfirmJob confirms the job once every key in the layer is present. A missing
// key means the layer isn't ready yet, so the job keeps waiting rather than
// failing.
func (h *JobHandler) ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	var data LayerData
	if err := json.Unmarshal(job.Data, &data); err != nil {
		return orbital.CancelJobConfirmer(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	for _, keyID := range data.KeyIDs {
		if _, err := h.keyStore.GetKeyByID(ctx, keyID, data.TenantID); err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				return orbital.ContinueJobConfirmer(), nil
			}
			return nil, fmt.Errorf("confirm job: %w", err)
		}
	}

	return orbital.CompleteJobConfirmer(), nil
}

// ResolveTasks emits one task per key in the layer, targeted at the embedded
// operator. Already-active keys are not skipped here; the task handler
// short-circuits them, which keeps every job with at least one task.
func (h *JobHandler) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	var data LayerData
	if err := json.Unmarshal(job.Data, &data); err != nil {
		return orbital.CancelTaskResolver(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	infos := make([]orbital.TaskInfo, 0, len(data.KeyIDs))
	for _, keyID := range data.KeyIDs {
		taskData, err := json.Marshal(TaskData{TenantID: data.TenantID, KeyID: keyID})
		if err != nil {
			return orbital.CancelTaskResolver(fmt.Sprintf("marshal task data: %v", err)), nil
		}
		infos = append(infos, orbital.TaskInfo{
			Data:   taskData,
			Type:   TaskType,
			Target: h.localTarget,
		})
	}

	return orbital.CompleteTaskResolver().WithTaskInfo(infos), nil
}

func (h *JobHandler) OnJobDone(ctx context.Context, job orbital.Job) error {
	slogctx.Info(ctx, "activate-key layer completed", "jobID", job.ID)
	return nil
}

func (h *JobHandler) OnJobFailed(ctx context.Context, job orbital.Job) error {
	slogctx.Error(ctx, "activate-key layer failed", "jobID", job.ID, "error", job.ErrorMessage)
	return nil
}

func (h *JobHandler) OnJobCanceled(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "activate-key layer canceled", "jobID", job.ID)
	return nil
}
