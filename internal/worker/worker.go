// Package worker provides a simple periodic task scheduler.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// TaskFn is a function executed by a [Scheduler] on each tick.
type TaskFn func(context.Context) error

// Scheduler runs a [TaskFn] at a fixed interval until stopped via context cancellation or [Scheduler.Stop].
// [Scheduler.Start] may only be called once; subsequent calls are no-ops.
type Scheduler struct {
	interval  time.Duration
	task      TaskFn
	isStarted atomic.Bool
	stopOnce  sync.Once
	done      chan struct{}
}

var (
	ErrTaskFnNil       = errors.New("task function cannot be nil")
	ErrInvalidInterval = errors.New("interval must be greater than zero")
)

// New creates a [Scheduler] that executes task every interval.
// Returns an error if task is nil or interval is not positive.
func New(interval time.Duration, task TaskFn) (*Scheduler, error) {
	if task == nil {
		return nil, ErrTaskFnNil
	}
	if interval <= 0 {
		return nil, ErrInvalidInterval
	}

	return &Scheduler{
		interval: interval,
		task:     task,
		done:     make(chan struct{}),
	}, nil
}

// Start blocks, running the task on each tick until ctx is cancelled or [Scheduler.Stop] is called.
// Task errors are logged but do not stop the scheduler.
func (w *Scheduler) Start(ctx context.Context) {
	if !w.isStarted.CompareAndSwap(false, true) {
		slog.Warn("Worker already started")
		return
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := w.task(ctx); err != nil {
				slog.Error("Worker task", slog.String("error", err.Error()))
			}
		case <-ctx.Done():
			return
		case <-w.done:
			return
		}
	}
}

// Stop signals the scheduler to stop. It is safe to call multiple times.
func (w *Scheduler) Stop() {
	w.stopOnce.Do(func() {
		close(w.done)
	})
}
