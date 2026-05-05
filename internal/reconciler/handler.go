package reconciler

import (
	"context"

	"github.com/openkcm/orbital"
)

// JobHandler owns the Orbital lifecycle for a single Krypton job type.
type JobHandler interface {
	JobType() string
	ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error)
	ResolveTasks(ctx context.Context, job orbital.Job, cursor orbital.TaskResolverCursor) (orbital.TaskResolverResult, error)
	OnJobDone(ctx context.Context, job orbital.Job) error
	OnJobFailed(ctx context.Context, job orbital.Job) error
	OnJobCanceled(ctx context.Context, job orbital.Job) error
}
