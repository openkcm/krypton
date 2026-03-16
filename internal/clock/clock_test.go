package clock_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/clock"
)

func TestNowUTC(t *testing.T) {
	t.Run("returns current UTC timestamp", func(t *testing.T) {
		// given
		before := float64(time.Now().UTC().Unix())

		// when
		result := clock.NowUTC()

		// then
		after := float64(time.Now().UTC().Unix())
		assert.GreaterOrEqual(t, result, before)
		assert.LessOrEqual(t, result, after)
	})

	t.Run("returns non-zero value", func(t *testing.T) {
		// when
		result := clock.NowUTC()

		// then
		assert.NotZero(t, result)
	})

	t.Run("returns increasing values on subsequent calls", func(t *testing.T) {
		// when
		first := clock.NowUTC()
		time.Sleep(time.Millisecond)
		second := clock.NowUTC()

		// then
		assert.GreaterOrEqual(t, second, first)
	})
}
