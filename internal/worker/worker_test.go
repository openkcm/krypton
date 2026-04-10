package worker_test

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/worker"
)

func TestNew(t *testing.T) {
	t.Run("should return an error if the task function is nil", func(t *testing.T) {
		// given when
		_, err := worker.New(1*time.Second, nil)

		// then
		assert.ErrorIs(t, err, worker.ErrTaskFnNil)
	})

	t.Run("should return a Scheduler instance if the task function is not nil", func(t *testing.T) {
		// given
		taskFn := func(_ context.Context) error {
			return nil
		}

		// when
		subj, err := worker.New(1*time.Second, taskFn)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, subj)
	})

	t.Run("should return error if scheduler interval is", func(t *testing.T) {
		// given
		tts := []struct {
			name     string
			interval time.Duration
		}{
			{
				name:     "negative",
				interval: -1 * time.Second,
			},
			{
				name:     "zero",
				interval: 0,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				taskFn := func(_ context.Context) error {
					return nil
				}

				// when
				subj, err := worker.New(tt.interval, taskFn)

				// then
				assert.ErrorIs(t, err, worker.ErrInvalidInterval)
				assert.Nil(t, subj)
			})
		}
	})
}

func TestStart(t *testing.T) {
	t.Run("should execute the task function at the specified schedule", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// given
			ctx := t.Context()
			var actExecutedTimes atomic.Int32

			taskFn := func(_ context.Context) error {
				actExecutedTimes.Add(1)
				return nil
			}

			subj, err := worker.New(5*time.Second, taskFn)
			assert.NoError(t, err)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			// when
			go subj.Start(ctx)

			// then
			time.Sleep(11 * time.Second) // wait for the task to execute at least twice
			synctest.Wait()

			assert.Equal(t, int32(2), actExecutedTimes.Load())
		})
	})

	t.Run("should stop executing the task function when the context is canceled", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// given
			ctx := t.Context()
			ctx, cancel := context.WithCancel(ctx)

			var actExecutedTimes atomic.Int32
			taskFn := func(_ context.Context) error {
				actExecutedTimes.Add(1)
				cancel()
				return nil
			}

			subj, err := worker.New(5*time.Second, taskFn)
			assert.NoError(t, err)

			// when
			go subj.Start(ctx)

			// then
			time.Sleep(11 * time.Second) // wait for the task to execute at least twice
			synctest.Wait()

			assert.Equal(t, int32(1), actExecutedTimes.Load())
		})
	})

	t.Run("should execute the task function at the specified schedule even after taskFn returns an error", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// given
			ctx := t.Context()
			var actExecutedTimes atomic.Int32

			taskFn := func(_ context.Context) error {
				actExecutedTimes.Add(1)
				return assert.AnError
			}

			subj, err := worker.New(5*time.Second, taskFn)
			assert.NoError(t, err)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			// when
			go subj.Start(ctx)

			// then
			time.Sleep(11 * time.Second)
			synctest.Wait()

			assert.Equal(t, int32(2), actExecutedTimes.Load())
		})
	})

	t.Run("should start only once if Start is called multiple times", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// given
			ctx := t.Context()

			var actCalled atomic.Int32
			taskFn := func(_ context.Context) error {
				actCalled.Add(1)
				return nil
			}

			subj, err := worker.New(5*time.Second, taskFn)
			assert.NoError(t, err)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			// when
			go subj.Start(ctx)
			go subj.Start(ctx)

			time.Sleep(11 * time.Second)
			synctest.Wait()

			// then
			assert.Equal(t, int32(2), actCalled.Load())
		})
	})
}

func TestStop(t *testing.T) {
	t.Run("should stop executing the task function when Stop is called", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// given
			ctx := t.Context()
			var actExecutedTimes atomic.Int32

			taskFn := func(_ context.Context) error {
				actExecutedTimes.Add(1)
				return nil
			}

			subj, err := worker.New(5*time.Second, taskFn)
			assert.NoError(t, err)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			// when
			go subj.Start(ctx)

			time.Sleep(11 * time.Second) // wait for the task to execute at least twice
			synctest.Wait()
			subj.Stop()
			time.Sleep(11 * time.Second) // wait to ensure no more executions after Stop is called
			synctest.Wait()

			// then
			assert.Equal(t, int32(2), actExecutedTimes.Load())
		})
	})

	t.Run("should be safe to call Stop multiple times", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			// given
			ctx := t.Context()
			var actExecutedTimes atomic.Int32

			taskFn := func(_ context.Context) error {
				actExecutedTimes.Add(1)
				return nil
			}

			subj, err := worker.New(5*time.Second, taskFn)
			assert.NoError(t, err)

			ctx, cancel := context.WithCancel(ctx)
			defer cancel()

			// when
			go subj.Start(ctx)

			time.Sleep(11 * time.Second) // wait for the task to execute at least twice
			synctest.Wait()
			// call Stop multiple times
			subj.Stop()
			subj.Stop()
			time.Sleep(11 * time.Second) // wait to ensure no more executions after Stop is called
			synctest.Wait()

			// then
			assert.Equal(t, int32(2), actExecutedTimes.Load())
		})
	})
}
