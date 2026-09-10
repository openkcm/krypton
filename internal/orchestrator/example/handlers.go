package example

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/openkcm/orbital"
)

// Job, group, and task type identifiers. The orchestrator routes orbital
// callbacks to a handler by matching these strings, so each must be unique
// across the handlers registered on one manager.
const (
	// JobTypeActivateKey is the type of a single key-activation job.
	JobTypeActivateKey = "example.activate-key"
	// GroupTypeCascade is the type of the job group holding one activation
	// job per key in a hierarchy.
	GroupTypeCascade = "example.cascade-activation"
	// TaskTypeActivateKey is the type of the task an activation job resolves
	// into. It shares JobTypeActivateKey's identifier because each job
	// produces exactly one matching task.
	TaskTypeActivateKey = JobTypeActivateKey
)

// ActivateKeyData is the payload carried on both the job and the task it
// resolves into. It is JSON-encoded into orbital's Data field.
type ActivateKeyData struct {
	// KeyID is the key to activate.
	KeyID string `json:"key_id"`
	// ParentID is the key that must already be active; empty for the root.
	ParentID string `json:"parent_id,omitempty"`
	// Target names the operator that runs the activation task — the manager's
	// LocalTarget for root-managed keys, or a configured agent target name.
	Target string `json:"target"`
}

// ActivateKeyJobHandler is the orchestrator.JobHandler for key activation. It
// runs on the root: it confirms a key is ready to activate, resolves the job
// into a single activation task aimed at the owning operator, and records the
// outcome in the store when the job terminates.
type ActivateKeyJobHandler struct {
	store *KeyStore
	log   *slog.Logger
}

// NewActivateKeyJobHandler builds the job handler over the given store.
func NewActivateKeyJobHandler(store *KeyStore, log *slog.Logger) *ActivateKeyJobHandler {
	return &ActivateKeyJobHandler{store: store, log: log}
}

// JobType identifies the jobs this handler owns.
func (*ActivateKeyJobHandler) JobType() string { return JobTypeActivateKey }

// ConfirmJob gates the job: unknown key cancels, a not-yet-active parent asks
// orbital to retry later, and a ready key confirms. This is where the cascade
// ordering is enforced.
func (h *ActivateKeyJobHandler) ConfirmJob(_ context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	data, err := decode(job.Data)
	if err != nil {
		return orbital.CancelJobConfirmer(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	if _, known := h.store.State(data.KeyID); !known {
		return orbital.CancelJobConfirmer("unknown key: " + data.KeyID), nil
	}

	if !h.store.parentActive(data.ParentID) {
		// Parent not active yet — come back later rather than failing.
		return orbital.ContinueJobConfirmer(), nil
	}

	return orbital.CompleteJobConfirmer(), nil
}

// ResolveTasks turns the confirmed job into a single activation task, targeted
// at the operator named in the payload. The task runs on the embedded operator
// when Target is the manager's LocalTarget, or on a remote agent otherwise.
func (h *ActivateKeyJobHandler) ResolveTasks(_ context.Context, job orbital.Job, _ orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	data, err := decode(job.Data)
	if err != nil {
		return orbital.CancelTaskResolver(fmt.Sprintf("invalid job data: %v", err)), nil
	}

	return orbital.CompleteTaskResolver().WithTaskInfo([]orbital.TaskInfo{{
		Type:   TaskTypeActivateKey,
		Data:   job.Data,
		Target: data.Target,
	}}), nil
}

// OnJobDone marks the key active once its activation task has completed.
func (h *ActivateKeyJobHandler) OnJobDone(_ context.Context, job orbital.Job) error {
	data, err := decode(job.Data)
	if err != nil {
		return err
	}
	if !h.store.setState(data.KeyID, KeyActive) {
		return fmt.Errorf("activate: unknown key %s", data.KeyID)
	}
	h.log.Info("key activated", "key", data.KeyID)
	return nil
}

// OnJobFailed marks the key failed so the cascade does not silently stall.
func (h *ActivateKeyJobHandler) OnJobFailed(_ context.Context, job orbital.Job) error {
	data, err := decode(job.Data)
	if err != nil {
		return err
	}
	h.store.setState(data.KeyID, KeyFailed)
	h.log.Warn("key activation failed", "key", data.KeyID, "reason", job.ErrorMessage)
	return nil
}

// OnJobCanceled is a no-op: a cancel means the job was superseded or gated out,
// and must not clobber whatever state the key already reached.
func (h *ActivateKeyJobHandler) OnJobCanceled(_ context.Context, _ orbital.Job) error {
	return nil
}

// CascadeGroupHandler is the orchestrator.JobGroupHandler for the whole
// cascade. Orbital calls it once the group of activation jobs terminates.
type CascadeGroupHandler struct {
	log *slog.Logger
}

// NewCascadeGroupHandler builds the group handler.
func NewCascadeGroupHandler(log *slog.Logger) *CascadeGroupHandler {
	return &CascadeGroupHandler{log: log}
}

// JobGroupType identifies the groups this handler owns.
func (*CascadeGroupHandler) JobGroupType() string { return GroupTypeCascade }

// OnJobGroupDone fires when every activation in the cascade has completed.
func (h *CascadeGroupHandler) OnJobGroupDone(_ context.Context, group orbital.JobGroup) error {
	h.log.Info("cascade complete", "group", group.ID, "keys", len(group.Jobs))
	return nil
}

// OnJobGroupFailed fires when the cascade could not finish.
func (h *CascadeGroupHandler) OnJobGroupFailed(_ context.Context, group orbital.JobGroup) error {
	h.log.Warn("cascade failed", "group", group.ID)
	return nil
}

// OnJobGroupCanceled fires when the cascade was canceled.
func (h *CascadeGroupHandler) OnJobGroupCanceled(_ context.Context, group orbital.JobGroup) error {
	h.log.Info("cascade canceled", "group", group.ID)
	return nil
}

// ActivateKeyTaskHandler is the orchestrator.TaskHandler that performs the
// actual activation. It runs inside the operator that owns the key: in-process
// via the embedded operator for root-managed keys, or on a remote agent. The
// orchestrator dispatches the task here purely by matching TaskType — the body
// below is the whole of the handler author's concern.
type ActivateKeyTaskHandler struct {
	store *KeyStore
	log   *slog.Logger
}

// NewActivateKeyTaskHandler builds the task handler over the operator-local store.
func NewActivateKeyTaskHandler(store *KeyStore, log *slog.Logger) *ActivateKeyTaskHandler {
	return &ActivateKeyTaskHandler{store: store, log: log}
}

// TaskType identifies the tasks this handler runs.
func (*ActivateKeyTaskHandler) TaskType() string { return TaskTypeActivateKey }

// Handle performs the activation. Corrupt data is a terminal failure; anything
// else completes. A real handler might run a multi-step state machine here and
// call resp.ContinueAndWaitFor between steps — the orchestrator neither knows
// nor cares.
func (h *ActivateKeyTaskHandler) Handle(_ context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	data, err := decode(req.TaskData)
	if err != nil {
		resp.Fail(fmt.Sprintf("invalid task data: %v", err))
		return
	}

	h.log.Info("activating key on operator", "key", data.KeyID, "task", req.TaskID)
	if !h.store.setState(data.KeyID, KeyActive) {
		resp.Fail("unknown key: " + data.KeyID)
		return
	}

	resp.Complete()
}

func decode(raw []byte) (ActivateKeyData, error) {
	var data ActivateKeyData
	if err := json.Unmarshal(raw, &data); err != nil {
		return ActivateKeyData{}, err
	}
	return data, nil
}
