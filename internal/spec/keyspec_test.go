package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func TestKeySpec(t *testing.T) {
	t.Run("Usage", func(t *testing.T) {
		// given
		tts := []struct {
			name     string
			input    spec.KeySpec
			expUsage spec.KeyUsage
		}{
			{
				name: "should return wrap and unwrap for 'root' role",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleRoot,
					Algorithm: spec.KeyAlgorithmAES256,
				},
				expUsage: spec.KeyUsageWrap | spec.KeyUsageUnwrap,
			},
			{
				name: "should return wrap and unwrap for 'kek' role",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleKek,
					Algorithm: spec.KeyAlgorithmAES256,
				},
				expUsage: spec.KeyUsageWrap | spec.KeyUsageUnwrap,
			},
			{
				name: "should return wrap and unwrap for 'tek' role",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleTek,
					Algorithm: spec.KeyAlgorithmAES256,
				},
				expUsage: spec.KeyUsageWrap | spec.KeyUsageUnwrap,
			},
			{
				name: "should return encrypt and decrypt for 'dek' role",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleDek,
					Algorithm: spec.KeyAlgorithmAES256,
				},
				expUsage: spec.KeyUsageEncrypt | spec.KeyUsageDecrypt,
			},
			{
				name: "should return zero usage for an invalid role",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      "invalid-role",
					Algorithm: spec.KeyAlgorithmAES256,
				},
				expUsage: spec.KeyUsageNone,
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
			input  spec.KeySpec
			expErr error
		}{
			{
				name: "should return error if kind is empty",
				input: spec.KeySpec{
					Kind:      "",
					Role:      spec.KeyRoleRoot,
					Algorithm: spec.KeyAlgorithmAES256,
					LabelSpec: spec.LabelSpec{AllowUserLabels: true},
				},
				expErr: spec.ErrKeySpecKindEmpty,
			},
			{
				name: "should return error if role is invalid",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      "invalid-role",
					Algorithm: spec.KeyAlgorithmAES256,
					LabelSpec: spec.LabelSpec{AllowUserLabels: true},
				},
				expErr: spec.ErrKeySpecRoleInvalid,
			},
			{
				name: "should return error if algorithm is empty",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleRoot,
					Algorithm: "",
					LabelSpec: spec.LabelSpec{AllowUserLabels: true},
				},
				expErr: spec.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return error if algorithm is invalid",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleRoot,
					Algorithm: "some-invalid-algorithm",
					LabelSpec: spec.LabelSpec{AllowUserLabels: true},
				},
				expErr: spec.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return nil if role is 'root'",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleRoot,
					Algorithm: spec.KeyAlgorithmAES256,
					LabelSpec: spec.LabelSpec{AllowUserLabels: true},
				},
			},
			{
				name: "should return nil if role is 'kek'",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleKek,
					Algorithm: spec.KeyAlgorithmAES256,
					LabelSpec: spec.LabelSpec{AllowUserLabels: true},
				},
			},
			{
				name: "should return nil if role is 'dek'",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleDek,
					Algorithm: spec.KeyAlgorithmAES256,
					LabelSpec: spec.LabelSpec{AllowUserLabels: true},
				},
			},
			{
				name: "should return nil if role is 'tek'",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleTek,
					Algorithm: spec.KeyAlgorithmAES256,
					LabelSpec: spec.LabelSpec{AllowUserLabels: true},
				},
			},
			{
				name: "should return error if LabelSpec validate fails",
				input: spec.KeySpec{
					Kind:      "K0",
					Role:      spec.KeyRoleTek,
					Algorithm: spec.KeyAlgorithmAES256,
					LabelSpec: spec.LabelSpec{AllowUserLabels: false},
				},
				expErr: spec.ErrLabelsSpecRequirementEmpty,
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
			input spec.KeyAlgorithm
			expOk bool
		}{
			{
				name:  "should return true for 'AES256'",
				input: spec.KeyAlgorithmAES256,
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
				ok := spec.IsSupportedAlgorithm(tt.input)

				// then
				assert.Equal(t, tt.expOk, ok)
			})
		}
	})
}
