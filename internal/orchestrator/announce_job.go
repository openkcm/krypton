package orchestrator

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// AnnounceJobHandler is the [JobHandler] for the announce-key job type.
// It confirms the job by transitioning the key to in-progress and resolves
// it into a single announce-key task.
type AnnounceJobHandler struct {
	transactor store.Transactor
}

var _ JobHandler = &AnnounceJobHandler{}

func NewAnnounceJobHandler(transactor store.Transactor) *AnnounceJobHandler {
	return &AnnounceJobHandler{
		transactor: transactor,
	}
}

func (h *AnnounceJobHandler) JobType() string {
	return AnnounceKey
}

func (h *AnnounceJobHandler) ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	var key model.Key
	if err := json.Unmarshal(job.Data, &key); err != nil {
		return orbital.CancelJobConfirmer(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	err := h.transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
		existing, err := stores.Keys.GetKeyByID(ctx, key.ID, key.TenantID)
		if err != nil {
			return err
		}

		if existing.KeyProcessingState.Status == model.KeyProcessingPending {
			err = stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
				ID:         key.ID,
				TenantID:   key.TenantID,
				ToState:    existing.LifeCycleState,
				ToStatus:   model.KeyProcessingInProgress,
				FromState:  []model.KeyLifeCycleState{existing.LifeCycleState},
				FromStatus: []model.KeyProcessingStatus{model.KeyProcessingPending},
			})
			if err != nil && !errors.Is(err, store.ErrKeyNotFound) {
				return err
			}
		}

		return nil
	})

	switch {
	case errors.Is(err, store.ErrKeyNotFound):
		return orbital.CancelJobConfirmer(fmt.Sprintf("key %s:%s not found", key.TenantID, key.ID)), nil
	case err != nil:
		return orbital.ContinueJobConfirmer(), nil
	default:
		return orbital.CompleteJobConfirmer(), nil
	}
}

func (h *AnnounceJobHandler) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	return orbital.CompleteTaskResolver().WithTaskInfo([]orbital.TaskInfo{{
		Data:   job.Data,
		Type:   AnnounceKey,
		Target: DefaultLocalTargetName,
	}}), nil
}

func (h *AnnounceJobHandler) OnJobDone(ctx context.Context, job orbital.Job) error {
	slogctx.Info(ctx, "announce-key job done", "jobID", job.ID)
	return nil
}

func (h *AnnounceJobHandler) OnJobFailed(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "announce-key job failed", "jobID", job.ID, "error", job.ErrorMessage)
	return nil
}

func (h *AnnounceJobHandler) OnJobCanceled(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "announce-key job canceled", "jobID", job.ID)
	return nil
}
