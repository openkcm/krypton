package models_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/models"
)

func TestKeyHierarchy(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		tts := []struct {
			name   string
			input  *models.KeyHierarchy
			expErr error
		}{
			{
				name: "should return error if hierarchy name is empty",
				input: &models.KeyHierarchy{
					Name: "",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyNameEmpty,
			},
			{
				name: "should return error if keys list is empty",
				input: &models.KeyHierarchy{
					Name:     "production-hierarchy",
					KeySpecs: []models.KeySpec{},
				},
				expErr: models.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "should return error if keys list is nil",
				input: &models.KeyHierarchy{
					Name:     "production-hierarchy",
					KeySpecs: nil,
				},
				expErr: models.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "should return error if first key is 'kek'",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if first key is 'dek'",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if first key is 'tek'",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleTek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if there are duplicate key kinds",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K0",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyDuplicateKind,
			},
			{
				name: "should return error if a key spec in the keys list has an invalid algorithm",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: "",
						},
					},
				},
				expErr: models.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return error if there are multiple 'root' keys",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyDuplicateRoot,
			},
			{
				name: "should return error if last key does not have role 'dek'",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return error if a dek key appears in an intermediate position",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K4",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyInvalidIntermediateKey,
			},
			{
				name: "should return error if there is a non-kek(dek) key in the middle of the hierarchy",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyInvalidIntermediateKey,
			},
			{
				name: "should return error if the hierarchy has root and kek keys",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return error if the hierarchy has root and tek keys",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleTek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: models.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return nil if the hierarchy has root and dek keys",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has root, kek, and dek keys",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has root, kek, tek and dek keys",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      models.KeyRoleTek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K4",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has only a root key",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
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
			input      *models.KeyHierarchy
			keyToCheck models.KeyKind
			expIsFound bool
			expKeySpec models.KeySpec
		}{
			{
				name: "should return the correct key spec for an existing key kind",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				keyToCheck: "K1",
				expIsFound: true,
				expKeySpec: models.KeySpec{
					Kind:      "K1",
					Role:      models.KeyRoleKek,
					Algorithm: models.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return false if the key kind does not exist in the hierarchy",
				input: &models.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []models.KeySpec{
						{
							Kind:      "K0",
							Role:      models.KeyRoleRoot,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      models.KeyRoleKek,
							Algorithm: models.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      models.KeyRoleDek,
							Algorithm: models.KeyAlgorithmAES256,
						},
					},
				},
				keyToCheck: "non-existent-key",
				expIsFound: false,
				expKeySpec: models.KeySpec{},
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
