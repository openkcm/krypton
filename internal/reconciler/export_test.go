package reconciler

import (
	"context"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/internal/config"
)

const DefaultMaxPendingReconciles = defaultMaxPendingReconciles
const NoJobHandlerRegisteredMessage = noJobHandlerRegisteredMessage

var BuildTargets = buildTargets
var JobHandlerNotFoundError = jobHandlerNotFoundError

func (m *Manager) OrbitalManager() *orbital.Manager {
	return m.orbitalManager
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

var NewTargetProvider = func(fn func(context.Context, config.ReconcilerTarget) (orbital.Initiator, error)) TargetProvider {
	return TargetProvider(fn)
}
