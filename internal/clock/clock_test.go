package clock_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/clock"
)

func TestNow(t *testing.T) {
	t.Run("returns current timestamp as nanoseconds", func(t *testing.T) {
		// given
		before := time.Now().UnixNano()

		// when
		result := clock.Now()

		// then
		after := time.Now().UnixNano()
		assert.GreaterOrEqual(t, int64(result), before)
		assert.LessOrEqual(t, int64(result), after)
	})

	t.Run("returns non-zero value", func(t *testing.T) {
		// when
		result := clock.Now()

		// then
		assert.NotZero(t, result)
	})

	t.Run("returns increasing values on subsequent calls", func(t *testing.T) {
		// when
		first := clock.Now()
		time.Sleep(time.Millisecond)
		second := clock.Now()

		// then
		assert.Greater(t, second, first)
	})
}
