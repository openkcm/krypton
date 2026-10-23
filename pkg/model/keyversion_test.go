package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/model"
)

func TestIsKnownKeyVersionState(t *testing.T) {
	tts := []struct {
		name  string
		input string
		ok    bool
	}{
		{
			name:  "usable is known",
			input: string(model.KeyVersionUsable),
			ok:    true,
		},
		{
			name:  "re-wrapping is known",
			input: string(model.KeyVersionReWrapping),
			ok:    true,
		},
		{
			name:  "activating is known",
			input: string(model.KeyVersionActivating),
			ok:    true,
		},
		{
			name:  "empty string is unknown",
			input: "",
			ok:    false,
		},
		{
			name:  "arbitrary string is unknown",
			input: "bogus",
			ok:    false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			actual := model.IsKnownKeyVersionState(tt.input)

			// then
			assert.Equal(t, tt.ok, actual)
		})
	}
}
