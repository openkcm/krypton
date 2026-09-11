package orchestrator

import (
	"context"

	"github.com/openkcm/orbital"
)

const (
	DefaultMaxPendingReconciles    = defaultMaxPendingReconciles
	NoJobHandlerRegisteredMessage  = noJobHandlerRegisteredMessage
	NoTaskHandlerRegisteredMessage = noTaskHandlerRegisteredMessage
)

var (
	BuildTaskHandlerMap     = buildTaskHandlerMap
	BuildGroupHandlerMap    = buildGroupHandlerMap
	NewTaskDispatch         = buildTaskDispatch
	JobHandlerNotFoundError = jobHandlerNotFoundError
)

func (o *Orchestrator) OrbitalManager() *orbital.Manager {
	return o.orbitalManager
}

// Targets returns a map containing the embedded operator target, mirroring what
// was passed to orbital. Used by tests to verify the embedded target is wired.
func (o *Orchestrator) Targets() map[string]orbital.TargetManager {
	return map[string]orbital.TargetManager{
		DefaultLocalTargetName: {Client: o.embeddedClient},
	}
}

func (o *Orchestrator) ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	return o.confirmJob(ctx, job)
}

func (o *Orchestrator) ResolveTasks(ctx context.Context, job orbital.Job, cursor orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	return o.resolveTasks(ctx, job, cursor)
}

func (o *Orchestrator) JobDone(ctx context.Context, job orbital.Job) error {
	return o.jobDone(ctx, job)
}

func (o *Orchestrator) JobFailed(ctx context.Context, job orbital.Job) error {
	return o.jobFailed(ctx, job)
}

func (o *Orchestrator) JobCanceled(ctx context.Context, job orbital.Job) error {
	return o.jobCanceled(ctx, job)
}

func (o *Orchestrator) JobGroupDone(ctx context.Context, group orbital.JobGroup) error {
	return o.jobGroupDone(ctx, group)
}

func (o *Orchestrator) JobGroupFailed(ctx context.Context, group orbital.JobGroup) error {
	return o.jobGroupFailed(ctx, group)
}

func (o *Orchestrator) JobGroupCanceled(ctx context.Context, group orbital.JobGroup) error {
	return o.jobGroupCanceled(ctx, group)
}
