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

	t.Run("Zero should not panic when input is nil", func(t *testing.T) {
		tts := []struct {
			name  string
			input []byte
			exp   []byte
		}{
			{name: "nil input", input: nil, exp: nil},
			{name: "empty input", input: []byte{}, exp: []byte{}},
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
