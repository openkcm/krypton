package reconciler

import (
	"time"

	"github.com/openkcm/orbital"
)

type Option func(manager *orbital.Manager)

func WithMaxPendingReconciles(n uint64) Option {
	return func(m *orbital.Manager) {
		m.Config.MaxPendingReconciles = n
	}
}

func WithConfirmJobAfter(d time.Duration) Option {
	return func(m *orbital.Manager) {
		m.Config.ConfirmJobAfter = d
	}
}

func WithExecInterval(d time.Duration) Option {
	return func(m *orbital.Manager) {
		m.Config.ConfirmJobWorkerConfig.ExecInterval = d
		m.Config.CreateTasksWorkerConfig.ExecInterval = d
		m.Config.ReconcileWorkerConfig.ExecInterval = d
		m.Config.NotifyWorkerConfig.ExecInterval = d
		m.Config.NotifyJobGroupWorkerConfig.ExecInterval = d
		m.Config.ScheduleJobGroupWorkerConfig.ExecInterval = d
	}
}
