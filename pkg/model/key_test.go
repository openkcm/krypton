package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/model"
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
							Role:      "root",
							Algorithm: "AES256",
							Usage:     []string{"encrypt"},
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
				expErr: model.ErrHierarchyKeysListEmpty,
			},
			{
				name: "if keys list is nil",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: nil,
				},
				expErr: model.ErrHierarchyKeysListEmpty,
			},
			{
				name: "if first key does not have role 'root'",

				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      "kek",
							Algorithm: "AES256",
							Usage:     []string{"encrypt"},
						},
					},
				},
				expErr: model.ErrHierarchyFirstKeyNotRoot,
			},
			{
				name: "if there are duplicate key kinds",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      "root",
							Algorithm: "AES256",
							Usage:     []string{"encrypt"},
						},
						{
							Kind:      "K0",
							Role:      "kek",
							Algorithm: "AES256",
							Usage:     []string{"encrypt"},
						},
					},
				},
				expErr: model.ErrHierarchyDuplicateKind,
			},
			{
				name: "if there is an invalid key spec in the keys list",
				input: model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      "root",
							Algorithm: "",
							Usage:     []string{"encrypt"},
						},
					},
				},
				expErr: model.ErrKeySpecAlgorithmEmpty,
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
					Role:      "root",
					Algorithm: "AES256",
					Usage:     []string{"encrypt"},
				},
				{
					Kind:      "K1",
					Role:      "kek",
					Algorithm: "AES256",
					Usage:     []string{"encrypt"},
				},
				{
					Kind:      "K2",
					Role:      "dek",
					Algorithm: "AES256",
					Usage:     []string{"encrypt", "decrypt"},
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
					Role:      "root",
					Algorithm: "AES256",
					Usage:     []string{"encrypt"},
				},
				expErr: model.ErrKeySpecNameEmpty,
			},
			{
				name: "if role is invalid",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      "invalid-role",
					Algorithm: "AES256",
					Usage:     []string{"encrypt"},
				},
				expErr: model.ErrKeySpecRoleInvalid,
			},
			{
				name: "if algorithm is empty",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      "root",
					Algorithm: "",
					Usage:     []string{"encrypt"},
				},
				expErr: model.ErrKeySpecAlgorithmEmpty,
			},
			{
				name: "if usage list is empty",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      "root",
					Algorithm: "AES256",
					Usage:     []string{},
				},
				expErr: model.ErrKeySpecUsageListEmpty,
			},
			{
				name: "if usage list contains a empty",
				input: model.KeySpec{
					Kind:      "K0",
					Role:      "root",
					Algorithm: "AES256",
					Usage: []string{
						"decrypt",
						"",
						"wrap",
						"unwrap",
					},
				},
				expErr: model.ErrKeySpecUsageListEmpty,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				err := tt.input.Validate()
				assert.Error(t, err)
				assert.EqualError(t, err, tt.expErr.Error())
			})
		}
	})

	t.Run("should return nil if valid", func(t *testing.T) {
		// given
		keySpec := model.KeySpec{
			Kind:      "K0",
			Role:      "root",
			Algorithm: "AES256",
			Usage:     []string{"encrypt"},
		}

		// when
		err := keySpec.Validate()

		// then
		assert.NoError(t, err)
	})
}
