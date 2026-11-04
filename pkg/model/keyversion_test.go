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

func TestKeyVersion_WithLabels(t *testing.T) {
	kv := model.KeyVersion{KeyID: "key1"}
	labels := model.Labels{"environment": "test"}

	actual := kv.WithLabels(labels)

	assert.Equal(t, labels, actual.Labels)
	assert.Nil(t, kv.Labels)
}

func TestKeyVersion_AAD(t *testing.T) {
	kv := model.KeyVersion{
		TenantID: "tenant1",
		KeyID:    "key1",
		Version:  11,
		Revision: 22,
	}

	actual := kv.AAD()

	assert.Equal(t, []byte("tenant1:key1:11:22"), actual)
}
