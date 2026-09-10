package orchestrator

import (
	"context"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/internal/config"
)

const (
	DefaultMaxPendingReconciles    = defaultMaxPendingReconciles
	NoJobHandlerRegisteredMessage  = noJobHandlerRegisteredMessage
	NoTaskHandlerRegisteredMessage = noTaskHandlerRegisteredMessage
)

var (
	BuildTargets            = buildTargets
	BuildTaskHandlerMap     = buildTaskHandlerMap
	BuildGroupHandlerMap    = buildGroupHandlerMap
	NewTaskDispatch         = buildTaskDispatch
	JobHandlerNotFoundError = jobHandlerNotFoundError
)

var NewTargetProvider = func(fn func(context.Context, config.ReconcilerTarget) (orbital.Initiator, error)) TargetProvider {
	return TargetProvider(fn)
}

func (m *Manager) OrbitalManager() *orbital.Manager {
	return m.orbitalManager
}

// Targets exposes the resolved target map (config rpc targets plus the embedded
// operator when task handlers are registered).
func (m *Manager) Targets() map[string]orbital.TargetManager {
	return m.targets
}

func (m *Manager) ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	return m.confirmJob(ctx, job)
}

func (m *Manager) ResolveTasks(ctx context.Context, job orbital.Job, cursor orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	return m.resolveTasks(ctx, job, cursor)
}

func (m *Manager) JobDone(ctx context.Context, job orbital.Job) error {
	return m.jobDone(ctx, job)
}

func (m *Manager) JobFailed(ctx context.Context, job orbital.Job) error {
	return m.jobFailed(ctx, job)
}

func (m *Manager) JobCanceled(ctx context.Context, job orbital.Job) error {
	return m.jobCanceled(ctx, job)
}

func (m *Manager) JobGroupDone(ctx context.Context, group orbital.JobGroup) error {
	return m.jobGroupDone(ctx, group)
}

func (m *Manager) JobGroupFailed(ctx context.Context, group orbital.JobGroup) error {
	return m.jobGroupFailed(ctx, group)
}

func (m *Manager) JobGroupCanceled(ctx context.Context, group orbital.JobGroup) error {
	return m.jobGroupCanceled(ctx, group)
}
