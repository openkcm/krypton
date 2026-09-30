package activatekey

import (
	"context"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"
)

// JobGroupHandler owns the orbital lifecycle for a whole cascading activation
// (one job group = one key hierarchy). It is logging-only: per-key state is
// finalized by the task handler, and per-layer failures by the job handler, so
// the group callbacks only need to record the overall outcome.
type JobGroupHandler struct{}

// NewJobGroupHandler builds the activation job-group handler.
func NewJobGroupHandler() *JobGroupHandler {
	return &JobGroupHandler{}
}

func (h *JobGroupHandler) JobGroupType() string {
	return GroupType
}

func (h *JobGroupHandler) OnJobGroupDone(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Info(ctx, "cascading activation completed", "jobGroupID", group.ID)
	return nil
}

func (h *JobGroupHandler) OnJobGroupFailed(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Error(ctx, "cascading activation failed", "jobGroupID", group.ID)
	return nil
}

func (h *JobGroupHandler) OnJobGroupCanceled(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Warn(ctx, "cascading activation canceled", "jobGroupID", group.ID)
	return nil
}
