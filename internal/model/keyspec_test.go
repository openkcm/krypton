package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/model"
)

func TestKeySpec(t *testing.T) {
	t.Run("Usage", func(t *testing.T) {
		// given
		tts := []struct {
			name     string
			input    model.KeySpec
			expUsage model.KeyUsage
		}{
			{
				name: "should return wrap and unwrap for 'root' role",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
				},
				expUsage: model.KeyUsageWrap | model.KeyUsageUnwrap,
			},
			{
				name: "should return wrap and unwrap for 'kek' role",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleKek,
					Algorithm: model.KeyAlgorithmAES256,
				},
				expUsage: model.KeyUsageWrap | model.KeyUsageUnwrap,
			},
			{
				name: "should return wrap and unwrap for 'tek' role",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleTek,
					Algorithm: model.KeyAlgorithmAES256,
				},
				expUsage: model.KeyUsageWrap | model.KeyUsageUnwrap,
			},
			{
				name: "should return encrypt and decrypt for 'dek' role",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleDek,
					Algorithm: model.KeyAlgorithmAES256,
				},
				expUsage: model.KeyUsageEncrypt | model.KeyUsageDecrypt,
			},
			{
				name: "should return zero usage for an invalid role",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      "invalid-role",
					Algorithm: model.KeyAlgorithmAES256,
				},
				expUsage: model.KeyUsageNone,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				usage := tt.input.Usage()

				// then
				assert.Equal(t, tt.expUsage, usage)
			})
		}
	})

	t.Run("Validate", func(t *testing.T) {
		tts := []struct {
			name   string
			input  model.KeySpec
			expErr error
		}{
			{
				name: "should return error if kind is empty",
				input: model.KeySpec{
					Kind:      "",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
				},
				expErr: model.ErrKeySpecKindEmpty,
			},
			{
				name: "should return error if role is invalid",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      "invalid-role",
					Algorithm: model.KeyAlgorithmAES256,
				},
				expErr: model.ErrKeySpecRoleInvalid,
			},
			{
				name: "should return error if algorithm is empty",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: "",
				},
				expErr: model.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return error if algorithm is invalid",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: "some-invalid-algorithm",
				},
				expErr: model.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return nil if role is 'root'",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return nil if role is 'kek'",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleKek,
					Algorithm: model.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return nil if role is 'dek'",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleDek,
					Algorithm: model.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return nil if role is 'tek'",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleTek,
					Algorithm: model.KeyAlgorithmAES256,
				},
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err := tt.input.Validate()

				// then
				if tt.expErr != nil {
					assert.Error(t, err)
					assert.ErrorIs(t, err, tt.expErr)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})

	t.Run("IsSupportedAlgorithm", func(t *testing.T) {
		tts := []struct {
			name  string
			input model.KeyAlgorithm
			expOk bool
		}{
			{
				name:  "should return true for 'AES256'",
				input: model.KeyAlgorithmAES256,
				expOk: true,
			},
			{
				name:  "should return false for an unsupported algorithm",
				input: "unsupported-algorithm",
				expOk: false,
			},
			{
				name:  "should return false for an empty algorithm",
				input: "",
				expOk: false,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				ok := model.IsSupportedAlgorithm(tt.input)

				// then
				assert.Equal(t, tt.expOk, ok)
			})
		}
	})
}
