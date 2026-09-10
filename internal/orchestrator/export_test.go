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

// Targets exposes the resolved target map (the embedded operator when task
// handlers are registered).
func (o *Orchestrator) Targets() map[string]orbital.TargetManager {
	return o.targets
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
