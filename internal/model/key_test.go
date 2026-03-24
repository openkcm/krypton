package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/model"
)

func TestKeyHierarchyValidate(t *testing.T) {
	t.Run("should return error", func(t *testing.T) {
		tts := []struct {
			name   string
			input  model.KeyHierarchy
			expErr error
		}{
			{
				name: "if hierarchy name is empty",
				input: model.KeyHierarchy{
					Name: "",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
							Usage:     model.KeyUsageEncrypt,
						},
					},
				},
				expErr: model.ErrKeyHierarchyNameEmpty,
			},
			{
				name: "if keys list is empty",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{},
				},
				expErr: model.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "if keys list is nil",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: nil,
				},
				expErr: model.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "if first key does not have role 'root'",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
							Usage:     model.KeyUsageEncrypt,
						},
					},
				},
				expErr: model.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "if there are duplicate key kinds",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
							Usage:     model.KeyUsageEncrypt,
						},
						{
							Kind:      "K0",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
							Usage:     model.KeyUsageEncrypt,
						},
					},
				},
				expErr: model.ErrKeyHierarchyDuplicateKind,
			},
			{
				name: "if there is an invalid key spec in the keys list",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: "",
							Usage:     model.KeyUsageEncrypt,
						},
					},
				},
				expErr: model.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "if there are multiple 'root' keys",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
							Usage:     model.KeyUsageEncrypt,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
							Usage:     model.KeyUsageEncrypt,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
							Usage:     model.KeyUsageDecrypt,
						},
					},
				},
				expErr: model.ErrKeyHierarchyDuplicateRoot,
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.input.Validate()
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})

	t.Run("should return nil if valid", func(t *testing.T) {
		// given
		hierarchy := model.KeyHierarchy{
			Name: "production-hierarchy",
			Keys: []model.KeySpec{
				{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt,
				},
				{
					Kind:      "K1",
					Role:      model.KeyRoleKek,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt,
				},
				{
					Kind:      "K2",
					Role:      model.KeyRoleDek,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt | model.KeyUsageDecrypt,
				},
				{
					Kind:      "K3",
					Role:      model.KeyRoleDek,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageUnwrap,
				},
				{
					Kind:      "K4",
					Role:      model.KeyRoleDek,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageWrap,
				},
			},
		}

		// when
		err := hierarchy.Validate()

		// then
		assert.NoError(t, err)
	})
}

func TestKeySpec(t *testing.T) {
	t.Run("should return error", func(t *testing.T) {
		tts := []struct {
			name   string
			input  model.KeySpec
			expErr error
		}{
			{
				name: "if kind is empty",
				input: model.KeySpec{
					Kind:      "",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt,
				},
				expErr: model.ErrKeySpecKindEmpty,
			},
			{
				name: "if role is invalid",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      "invalid-role",
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt,
				},
				expErr: model.ErrKeySpecRoleInvalid,
			},
			{
				name: "if algorithm is empty",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: "",
					Usage:     model.KeyUsageEncrypt,
				},
				expErr: model.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "if algorithm is invalid",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: "some-invalid-algorithm",
					Usage:     model.KeyUsageEncrypt,
				},
				expErr: model.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "if usage is zero",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     0,
				},
				expErr: model.ErrKeySpecUsageInvalid,
			},
			{
				name: "if usage contains an invalid value",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageDecrypt | model.KeyUsageEncrypt | 16, // 16 is an invalid usage
				},
				expErr: model.ErrKeySpecUsageInvalid,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.input.Validate()
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})

	t.Run("should return nil if valid", func(t *testing.T) {
		tts := []struct {
			name   string
			input  model.KeySpec
			expErr error
		}{
			{
				name: "if usage is only encrypt",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt,
				},
				expErr: nil,
			},
			{
				name: "if usage is only decrypt",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageDecrypt,
				},
				expErr: nil,
			},
			{
				name: "if usage is only unwrap",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageUnwrap,
				},
				expErr: nil,
			},
			{
				name: "if usage is only wrap",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageWrap,
				},
				expErr: nil,
			},
			{
				name: "if usage is encrypt and decrypt",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt | model.KeyUsageDecrypt,
				},
				expErr: nil,
			},
			{
				name: "if usage is all valid values",
				input: model.KeySpec{
					Kind:      "K	0",
					Role:      model.KeyRoleRoot,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt | model.KeyUsageDecrypt | model.KeyUsageWrap | model.KeyUsageUnwrap,
				},
				expErr: nil,
			},
			{
				name: "if role is 'kek'",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleKek,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt,
				},
				expErr: nil,
			},
			{
				name: "if role is 'dek'",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      model.KeyRoleDek,
					Algorithm: model.KeyAlgorithmAES256,
					Usage:     model.KeyUsageEncrypt,
				},
				expErr: nil,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.input.Validate()
				assert.NoError(t, err)
			})
		}
	})
}
