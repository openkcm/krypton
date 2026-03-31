package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/model"
)

func TestKeyHierarchy(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		tts := []struct {
			name   string
			input  *model.KeyHierarchy
			expErr error
		}{
			{
				name: "should return error if hierarchy name is empty",
				input: &model.KeyHierarchy{
					Name: "",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyNameEmpty,
			},
			{
				name: "should return error if keys list is empty",
				input: &model.KeyHierarchy{
					Name:     "production-hierarchy",
					KeySpecs: []model.KeySpec{},
				},
				expErr: model.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "should return error if keys list is nil",
				input: &model.KeyHierarchy{
					Name:     "production-hierarchy",
					KeySpecs: nil,
				},
				expErr: model.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "should return error if first key is 'kek'",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if first key is 'dek'",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if first key is 'tek'",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleTek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if there are duplicate key kinds",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K0",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyDuplicateKind,
			},
			{
				name: "should return error if a key spec in the keys list has an invalid algorithm",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: "",
						},
					},
				},
				expErr: model.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return error if there are multiple 'root' keys",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyDuplicateRoot,
			},
			{
				name: "should return error if last key does not have role 'dek'",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return error if a dek key appears in an intermediate position",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K4",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyInvalidIntermediateKey,
			},
			{
				name: "should return error if there is a non-kek(dek) key in the middle of the hierarchy",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyInvalidIntermediateKey,
			},
			{
				name: "should return error if the hierarchy has root and kek keys",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return error if the hierarchy has root and tek keys",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleTek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: model.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return nil if the hierarchy has root and dek keys",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has root, kek, and dek keys",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has root, kek, tek and dek keys",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleTek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K4",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has only a root key",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
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

	t.Run("FindKeySpec", func(t *testing.T) {
		// given
		tts := []struct {
			name       string
			input      *model.KeyHierarchy
			keyToCheck model.KeyKind
			expIsFound bool
			expKeySpec model.KeySpec
		}{
			{
				name: "should return the correct key spec for an existing key kind",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				keyToCheck: "K1",
				expIsFound: true,
				expKeySpec: model.KeySpec{
					Kind:      "K1",
					Role:      model.KeyRoleKek,
					Algorithm: model.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return false if the key kind does not exist in the hierarchy",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      model.KeyRoleKek,
							Algorithm: model.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      model.KeyRoleDek,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				keyToCheck: "non-existent-key",
				expIsFound: false,
				expKeySpec: model.KeySpec{},
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				keySpec, ok := tt.input.FindKeySpec(tt.keyToCheck)

				// then
				assert.Equal(t, tt.expIsFound, ok)
				assert.Equal(t, tt.expKeySpec, keySpec)
			})
		}
	})
}
