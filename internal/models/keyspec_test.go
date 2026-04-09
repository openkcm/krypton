package models_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/models"
)

func TestKeySpec(t *testing.T) {
	t.Run("Usage", func(t *testing.T) {
		// given
		tts := []struct {
			name     string
			input    models.KeySpec
			expUsage models.KeyUsage
		}{
			{
				name: "should return wrap and unwrap for 'root' role",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleRoot,
					Algorithm: models.KeyAlgorithmAES256,
				},
				expUsage: models.KeyUsageWrap | models.KeyUsageUnwrap,
			},
			{
				name: "should return wrap and unwrap for 'kek' role",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleKek,
					Algorithm: models.KeyAlgorithmAES256,
				},
				expUsage: models.KeyUsageWrap | models.KeyUsageUnwrap,
			},
			{
				name: "should return wrap and unwrap for 'tek' role",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleTek,
					Algorithm: models.KeyAlgorithmAES256,
				},
				expUsage: models.KeyUsageWrap | models.KeyUsageUnwrap,
			},
			{
				name: "should return encrypt and decrypt for 'dek' role",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleDek,
					Algorithm: models.KeyAlgorithmAES256,
				},
				expUsage: models.KeyUsageEncrypt | models.KeyUsageDecrypt,
			},
			{
				name: "should return zero usage for an invalid role",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      "invalid-role",
					Algorithm: models.KeyAlgorithmAES256,
				},
				expUsage: models.KeyUsageNone,
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
			input  models.KeySpec
			expErr error
		}{
			{
				name: "should return error if kind is empty",
				input: models.KeySpec{
					Kind:      "",
					Role:      models.KeyRoleRoot,
					Algorithm: models.KeyAlgorithmAES256,
				},
				expErr: models.ErrKeySpecKindEmpty,
			},
			{
				name: "should return error if role is invalid",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      "invalid-role",
					Algorithm: models.KeyAlgorithmAES256,
				},
				expErr: models.ErrKeySpecRoleInvalid,
			},
			{
				name: "should return error if algorithm is empty",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleRoot,
					Algorithm: "",
				},
				expErr: models.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return error if algorithm is invalid",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleRoot,
					Algorithm: "some-invalid-algorithm",
				},
				expErr: models.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return nil if role is 'root'",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleRoot,
					Algorithm: models.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return nil if role is 'kek'",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleKek,
					Algorithm: models.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return nil if role is 'dek'",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleDek,
					Algorithm: models.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return nil if role is 'tek'",
				input: models.KeySpec{
					Kind:      "K0",
					Role:      models.KeyRoleTek,
					Algorithm: models.KeyAlgorithmAES256,
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
			input models.KeyAlgorithm
			expOk bool
		}{
			{
				name:  "should return true for 'AES256'",
				input: models.KeyAlgorithmAES256,
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
				ok := models.IsSupportedAlgorithm(tt.input)

				// then
				assert.Equal(t, tt.expOk, ok)
			})
		}
	})
}
