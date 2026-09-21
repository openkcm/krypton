// Package announcekeyv2 hosts the handlers for the newly introduced
// orchestrator.Orchestrator. It replaces announcekey once key_service.go
// is adjusted.
package announcekeyv2

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/internal/orchestrator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

const JobType = "announce-key"

type JobHandler struct {
	keyStore store.Key
}

var _ orchestrator.JobHandler = &JobHandler{}

func NewJobHandler(keyStore store.Key) *JobHandler {
	return &JobHandler{
		keyStore: keyStore,
	}
}

func (h *JobHandler) JobType() string {
	return JobType
}

func (h *JobHandler) ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	var key model.Key
	if err := json.Unmarshal(job.Data, &key); err != nil {
		return orbital.CancelJobConfirmer(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	_, err := h.keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return orbital.CancelJobConfirmer(fmt.Sprintf("key %s:%s not found", key.TenantID, key.ID)), nil
		}
		return orbital.ContinueJobConfirmer(), nil
	}

	return orbital.CompleteJobConfirmer(), nil
}

func (h *JobHandler) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	return orbital.CompleteTaskResolver().WithTaskInfo([]orbital.TaskInfo{{
		Data:   job.Data,
		Type:   JobType,
		Target: orchestrator.DefaultLocalTargetName,
	}}), nil
}

func (h *JobHandler) OnJobDone(ctx context.Context, job orbital.Job) error {
	slogctx.Info(ctx, "announce-key job done", "jobID", job.ID)
	return nil
}

func (h *JobHandler) OnJobFailed(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "announce-key job failed", "jobID", job.ID, "error", job.ErrorMessage)
	return nil
}

func (h *JobHandler) OnJobCanceled(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "announce-key job canceled", "jobID", job.ID)
	return nil
}
