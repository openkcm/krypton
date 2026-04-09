package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func TestKeyHierarchy(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		tts := []struct {
			name   string
			input  *spec.KeyHierarchy
			expErr error
		}{
			{
				name: "should return error if hierarchy name is empty",
				input: &spec.KeyHierarchy{
					Name: "",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyNameEmpty,
			},
			{
				name: "should return error if keys list is empty",
				input: &spec.KeyHierarchy{
					Name:     "production-hierarchy",
					KeySpecs: []spec.KeySpec{},
				},
				expErr: spec.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "should return error if keys list is nil",
				input: &spec.KeyHierarchy{
					Name:     "production-hierarchy",
					KeySpecs: nil,
				},
				expErr: spec.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "should return error if first key is 'kek'",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if first key is 'dek'",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if first key is 'tek'",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleTek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyFirstKeyNotRoot,
			},
			{
				name: "should return error if there are duplicate key kinds",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K0",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyDuplicateKind,
			},
			{
				name: "should return error if a key spec in the keys list has an invalid algorithm",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: "",
						},
					},
				},
				expErr: spec.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return error if there are multiple 'root' keys",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyDuplicateRoot,
			},
			{
				name: "should return error if last key does not have role 'dek'",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return error if a dek key appears in an intermediate position",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K4",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyInvalidIntermediateKey,
			},
			{
				name: "should return error if there is a non-kek(dek) key in the middle of the hierarchy",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyInvalidIntermediateKey,
			},
			{
				name: "should return error if the hierarchy has root and kek keys",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return error if the hierarchy has root and tek keys",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleTek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: spec.ErrKeyHierarchyLastKeyNotDek,
			},
			{
				name: "should return nil if the hierarchy has root and dek keys",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has root, kek, and dek keys",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has root, kek, tek and dek keys",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleTek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K3",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K4",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil if the hierarchy has only a root key",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
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
			input      *spec.KeyHierarchy
			keyToCheck spec.KeyKind
			expIsFound bool
			expKeySpec spec.KeySpec
		}{
			{
				name: "should return the correct key spec for an existing key kind",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				keyToCheck: "K1",
				expIsFound: true,
				expKeySpec: spec.KeySpec{
					Kind:      "K1",
					Role:      spec.KeyRoleKek,
					Algorithm: spec.KeyAlgorithmAES256,
				},
			},
			{
				name: "should return false if the key kind does not exist in the hierarchy",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:      "K0",
							Role:      spec.KeyRoleRoot,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleDek,
							Algorithm: spec.KeyAlgorithmAES256,
						},
					},
				},
				keyToCheck: "non-existent-key",
				expIsFound: false,
				expKeySpec: spec.KeySpec{},
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
