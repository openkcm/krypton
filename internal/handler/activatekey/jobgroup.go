package activatekey

import (
	"context"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/internal/orchestrator"
)

const JobGroupType = "activate-key"

type JobGroupHandler struct{}

var _ orchestrator.JobGroupHandler = &JobGroupHandler{}

func NewJobGroupHandler() *JobGroupHandler {
	return &JobGroupHandler{}
}

func (*JobGroupHandler) JobGroupType() string {
	return JobGroupType
}

func (*JobGroupHandler) OnJobGroupDone(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Info(ctx, "activate-key job group done", "jobGroupID", group.ID)
	return nil
}

func (*JobGroupHandler) OnJobGroupFailed(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Warn(ctx, "activate-key job group failed", "jobGroupID", group.ID, "error", group.ErrorMessage)
	return nil
}

func (*JobGroupHandler) OnJobGroupCanceled(ctx context.Context, group orbital.JobGroup) error {
	slogctx.Warn(ctx, "activate-key job group canceled", "jobGroupID", group.ID)
	return nil
}
