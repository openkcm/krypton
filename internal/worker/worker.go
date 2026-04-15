// Package worker provides a simple periodic task scheduler.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

type TaskFn func(context.Context) error

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

func (w *Scheduler) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cFn != nil {
		w.cFn()
		w.cFn = nil
	}
}

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
