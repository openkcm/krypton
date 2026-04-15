// Package worker provides a simple periodic task scheduler.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// TaskFn is a function executed periodically by the Scheduler.
// It receives a context that is cancelled when the scheduler stops.
type TaskFn func(context.Context) error

// Scheduler runs a TaskFn at a fixed interval. It is safe for concurrent use.
// Use [New] to create a Scheduler, [Scheduler.Start] to begin execution in a
// goroutine, and [Scheduler.Stop] to shut down.
type Scheduler struct {
	interval time.Duration
	task     TaskFn
	cFn      context.CancelFunc
	mu       sync.Mutex
}

var (
	ErrTaskFnNil       = errors.New("task function cannot be nil")
	ErrInvalidInterval = errors.New("interval must be greater than zero")
)

// New creates a Scheduler that calls t [TaskFn] every d [time.Duration].
func New(d time.Duration, t TaskFn) (*Scheduler, error) {
	if t == nil {
		return nil, ErrTaskFnNil
	}
	if d <= 0 {
		return nil, ErrInvalidInterval
	}

	return &Scheduler{
		interval: d,
		task:     t,
	}, nil
}

// Start begins periodic execution of the task. It blocks until the scheduler
// is stopped via [Scheduler.Stop] or the parent ctx is cancelled. Intended to
// be called in a goroutine. Duplicate calls while running are no-ops.
func (w *Scheduler) Start(ctx context.Context) {
	nCtx, ok := w.canStart(ctx)
	if !ok {
		return
	}

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := w.task(nCtx); err != nil {
				slog.Error("Worker task", slog.String("error", err.Error()))
			}
		case <-nCtx.Done():
			return
		}
	}
}

// Stop cancels the running scheduler. It is safe to call multiple times.
func (w *Scheduler) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cFn != nil {
		w.cFn()
		w.cFn = nil
	}
}

// canStart guards against duplicate starts. Returns a derived context and true
// if the scheduler was not already running.
func (w *Scheduler) canStart(ctx context.Context) (context.Context, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cFn != nil {
		slog.Warn("Scheduler already started; ignoring duplicate Start call")
		return nil, false
	}
	nCtx, cancel := context.WithCancel(ctx)
	w.cFn = cancel
	return nCtx, true
}
