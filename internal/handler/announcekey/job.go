package announcekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type JobHandler struct {
	keyStore store.Key
}

func NewJobHandler(keyStore store.Key) *JobHandler {
	return &JobHandler{keyStore: keyStore}
}

func (h *JobHandler) JobType() string {
	return JobType
}

// ConfirmJob is the second commit in the orbital double-commit pattern. It
// only confirms the job if the key exists in pre-activation lifecycle and is
// linked to *this* job's ID via KeyProcessingState — i.e. AnnounceKey wrote
// the linkage successfully and no later announce has rotated the JobID.
func (h *JobHandler) ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	var data TaskData
	if err := json.Unmarshal(job.Data, &data); err != nil {
		return orbital.CancelJobConfirmer(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	key, err := h.keyStore.GetKeyByID(ctx, data.KeyID, data.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			// ConfirmJob is idempotent and orbital will eventually
			// time out the job if the key never lands.
			return orbital.ContinueJobConfirmer(), nil
		}
		return nil, fmt.Errorf("confirm job: %w", err)
	}

	if key.LifeCycleState != model.KeyLifeCyclePreActivation {
		return orbital.CancelJobConfirmer(fmt.Sprintf("key not in pre-activation: %s", key.LifeCycleState)), nil
	}

	if key.KeyProcessingState.Status != model.KeyProcessingInProgress ||
		key.KeyProcessingState.JobID != job.ID.String() {
		return orbital.CancelJobConfirmer("key not linked to this job"), nil
	}

	return orbital.CompleteJobConfirmer(), nil
}

func (h *JobHandler) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	var data TaskData
	if err := json.Unmarshal(job.Data, &data); err != nil {
		return orbital.CancelTaskResolver(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	return orbital.CompleteTaskResolver().WithTaskInfo([]orbital.TaskInfo{{
		Data:   job.Data,
		Type:   TaskType,
		Target: data.Target,
	}}), nil
}

func (h *JobHandler) OnJobDone(ctx context.Context, job orbital.Job) error {
	slogctx.Info(ctx, "announce-key job completed", "jobID", job.ID)
	return h.markProcessing(ctx, job, model.KeyProcessingCompleted)
}

func (h *JobHandler) OnJobFailed(ctx context.Context, job orbital.Job) error {
	slogctx.Error(ctx, "announce-key job failed", "jobID", job.ID, "error", job.ErrorMessage)
	return h.markProcessing(ctx, job, model.KeyProcessingFailed)
}

func (h *JobHandler) OnJobCanceled(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "announce-key job canceled", "jobID", job.ID)
	return h.markProcessing(ctx, job, model.KeyProcessingFailed)
}

func (h *JobHandler) markProcessing(ctx context.Context, job orbital.Job, status string) error {
	var data TaskData
	if err := json.Unmarshal(job.Data, &data); err != nil {
		return fmt.Errorf("unmarshal job data: %w", err)
	}

	if err := h.keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
		ID:        data.KeyID,
		TenantID:  data.TenantID,
		NewStatus: status,
		NewJobID:  job.ID.String(),
	}); err != nil {
		return fmt.Errorf("update key processing state: %w", err)
	}

	return nil
}
