package clock_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/clock"
)

func TestNowUTC(t *testing.T) {
	t.Run("returns current UTC timestamp as nanoseconds", func(t *testing.T) {
		// given
		before := time.Now().UTC().UnixNano()

		// when
		result := clock.NowUnixUTC()

		// then
		after := time.Now().UTC().UnixNano()
		assert.GreaterOrEqual(t, result, before)
		assert.LessOrEqual(t, result, after)
	})

	t.Run("returns non-zero value", func(t *testing.T) {
		// when
		result := clock.NowUnixUTC()

		// then
		assert.NotZero(t, result)
	})

	t.Run("returns increasing values on subsequent calls", func(t *testing.T) {
		// when
		first := clock.NowUnixUTC()
		time.Sleep(time.Millisecond)
		second := clock.NowUnixUTC()

		// then
		assert.Greater(t, second, first)
	})
}
