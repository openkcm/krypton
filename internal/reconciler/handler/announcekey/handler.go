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

const (
	JobType  = "announce-key"
	TaskType = "announce-key"
)

type TaskData struct {
	KeyID    string            `json:"key_id"`
	TenantID string            `json:"tenant_id"`
	Kind     string            `json:"kind"`
	Name     string            `json:"name"`
	ParentID string            `json:"parent_id,omitempty"`
	Target   string            `json:"target"`
	Labels   map[string]string `json:"labels,omitempty"`
}

type Handler struct {
	keyStore store.Key
}

func NewHandler(keyStore store.Key) *Handler {
	return &Handler{keyStore: keyStore}
}

func (h *Handler) JobType() string {
	return JobType
}

func (h *Handler) ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	var data TaskData
	if err := json.Unmarshal(job.Data, &data); err != nil {
		return orbital.CancelJobConfirmer(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	_, err := h.keyStore.GetKeyByID(ctx, data.KeyID, data.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return orbital.CancelJobConfirmer(fmt.Sprintf("key not found: %v", err)), nil
		}
		return nil, fmt.Errorf("confirm job: %w", err)
	}

	return orbital.CompleteJobConfirmer(), nil
}

func (h *Handler) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
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

func (h *Handler) OnJobDone(ctx context.Context, job orbital.Job) error {
	slogctx.Info(ctx, "announce-key job completed", "jobID", job.ID)
	return nil
}

func (h *Handler) OnJobFailed(ctx context.Context, job orbital.Job) error {
	slogctx.Error(ctx, "announce-key job failed", "jobID", job.ID, "error", job.ErrorMessage)
	return h.markKeyAnnounceFailed(ctx, job)
}

func (h *Handler) OnJobCanceled(ctx context.Context, job orbital.Job) error {
	slogctx.Warn(ctx, "announce-key job canceled", "jobID", job.ID)
	return h.markKeyAnnounceFailed(ctx, job)
}

func (h *Handler) markKeyAnnounceFailed(ctx context.Context, job orbital.Job) error {
	var data TaskData
	if err := json.Unmarshal(job.Data, &data); err != nil {
		return fmt.Errorf("unmarshal job data: %w", err)
	}

	if err := h.keyStore.UpdateKeyState(ctx, store.UpdateKeyStateQuery{
		ID:       data.KeyID,
		TenantID: data.TenantID,
		NewState: model.KeyStateAnnounceFailed,
	}); err != nil {
		return fmt.Errorf("update key state: %w", err)
	}

	return nil
}
