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
	"github.com/openkcm/krypton/pkg/validator"
)

type JobHandler struct {
	keyValidator validator.KeyValidator
	keyStore     store.Key
}

func NewJobHandler(keyStore store.Key, keyValidator validator.KeyValidator) *JobHandler {
	return &JobHandler{keyStore: keyStore, keyValidator: keyValidator}
}

func (h *JobHandler) JobType() string {
	return JobType
}

// ConfirmJob checks that the key is present in the database and still valid.
// If everything is valid it confirms the job otherwise it cancels the job and marks the key as filed.
// If a job is stale it does not update the key status.
func (h *JobHandler) ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	var data TaskData
	if err := json.Unmarshal(job.Data, &data); err != nil {
		return orbital.CancelJobConfirmer(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	// @TODO: should be performed in a transaction
	key, err := h.keyStore.GetKeyByID(ctx, data.KeyID, data.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return orbital.ContinueJobConfirmer(), nil
		}
		return nil, fmt.Errorf("confirm job: %w", err)
	}

	if key.KeyProcessingState.JobID != job.ID.String() {
		return orbital.CancelJobConfirmer("stale job: key is linked to a different job"), nil
	}

	if key.LifeCycleState != model.KeyLifeCyclePreActivation {
		return orbital.CancelJobConfirmer(fmt.Sprintf("key not in pre-activation: %s", key.LifeCycleState)), nil
	}

	if vErr := h.keyValidator.ValidateKeyAnnounce(ctx, validator.AnnounceInput{
		TenantID:   data.TenantID,
		KeyKind:    data.Kind,
		Name:       data.Name,
		ParentID:   data.ParentID,
		TargetName: data.Target,
	}); vErr != nil {
		if err := h.markProcessing(ctx, job, model.KeyProcessingFailed); err != nil {
			return nil, err
		}
		return orbital.CancelJobConfirmer(fmt.Sprintf("announce no longer valid: %v", vErr)), nil
	}

	if err := h.markProcessing(ctx, job, model.KeyProcessingInProgress); err != nil {
		return nil, err
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
	return nil
}

func (h *JobHandler) markProcessing(ctx context.Context, job orbital.Job, status model.KeyProcessingStatus) error {
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
