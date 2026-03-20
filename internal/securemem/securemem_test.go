package securemem_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/securemem"
)

func TestSecureMem(t *testing.T) {
	t.Run("Zero", func(t *testing.T) {
		// given
		input := []byte("secret")

		// when
		securemem.Zero(input)

		// then
		assert.Equal(t, make([]byte, len(input)), input)
	})

	t.Run("Zero should not panic when", func(t *testing.T) {
		tts := []struct {
			name  string
			input []byte
			exp   []byte
		}{
			{name: "input is nil", input: nil, exp: nil},
			{name: "input is an empty byte slice", input: []byte{}, exp: []byte{}},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				securemem.Zero(tt.input)

				// then
				assert.Equal(t, tt.exp, tt.input)
			})
		}
	})
}

func TestNoDump(t *testing.T) {
	// given
	err := securemem.NoDump()

	// when then
	assert.NoError(t, err)
}

func TestNoDumpIdempotent(t *testing.T) {
	// given
	err := securemem.NoDump()
	assert.NoError(t, err)

	// when - calling a second time should not error
	err = securemem.NoDump()

	// then
	assert.NoError(t, err)
}

func TestZeroLargeBuffer(t *testing.T) {
	t.Run("should zero a large buffer", func(t *testing.T) {
		// given
		size := 64 * 1024 // 64KB
		input := make([]byte, size)
		for i := range input {
			input[i] = 0xFF
		}

		// when
		securemem.Zero(input)

		// then
		for i, b := range input {
			if b != 0 {
				t.Fatalf("expected byte at index %d to be 0, got %d", i, b)
			}
		}
	})
}
