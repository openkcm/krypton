package orchestrator

import (
	"time"

	"github.com/openkcm/orbital"
)

// Option customizes a Manager at construction time.
type Option func(*builderOptions)

// WithMaxPendingReconciles sets the orbital manager's MaxPendingReconciles.
func WithMaxPendingReconciles(n uint64) Option {
	return func(o *builderOptions) {
		o.orbitalMutators = append(o.orbitalMutators, func(m *orbital.Manager) {
			m.Config.MaxPendingReconciles = n
		})
	}
}

// WithConfirmJobAfter sets how long the orbital manager waits before confirming a job.
func WithConfirmJobAfter(d time.Duration) Option {
	return func(o *builderOptions) {
		o.orbitalMutators = append(o.orbitalMutators, func(m *orbital.Manager) {
			m.Config.ConfirmJobAfter = d
		})
	}
}

// WithExecInterval sets the exec interval for every orbital worker.
func WithExecInterval(d time.Duration) Option {
	return func(o *builderOptions) {
		o.orbitalMutators = append(o.orbitalMutators, func(m *orbital.Manager) {
			m.Config.ConfirmJobWorkerConfig.ExecInterval = d
			m.Config.CreateTasksWorkerConfig.ExecInterval = d
			m.Config.ReconcileWorkerConfig.ExecInterval = d
			m.Config.NotifyWorkerConfig.ExecInterval = d
			m.Config.NotifyJobGroupWorkerConfig.ExecInterval = d
			m.Config.ScheduleJobGroupWorkerConfig.ExecInterval = d
		})
	}
}

// WithTargetProvider registers a factory used to dial configured rpc target
// operators (remote agents). It is required when the config lists targets.
func WithTargetProvider(provider TargetProvider) Option {
	return func(o *builderOptions) {
		o.targetProvider = provider
	}
}

// WithLocalTargetName overrides the name under which the embedded operator is
// registered (default DefaultLocalTargetName).
func WithLocalTargetName(name string) Option {
	return func(o *builderOptions) {
		o.localTargetName = name
	}
}

// WithEmbeddedHandlerTimeout sets the per-task timeout for the embedded operator.
func WithEmbeddedHandlerTimeout(d time.Duration) Option {
	return func(o *builderOptions) {
		o.embeddedHandlerTimeout = d
	}
}

// WithEmbeddedBufferSize sets the link buffer size for the embedded operator.
func WithEmbeddedBufferSize(size int) Option {
	return func(o *builderOptions) {
		o.embeddedBufferSize = size
	}
}
