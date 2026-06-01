package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleTek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K0",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  "",
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
					},
				},
				expErr: spec.ErrKeySpecAlgorithmInvalid,
			},
			{
				name: "should return error if a key spec in the keys list has an invalid LabelsSpec",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: false},
						},
					},
				},
				expErr: spec.ErrLabelsSpecRequirementEmpty,
			},
			{
				name: "should return error if there are multiple 'root' keys",
				input: &spec.KeyHierarchy{
					Name: "production-hierarchy",
					KeySpecs: []spec.KeySpec{
						{
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K2",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K3",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K2",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K2",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K3",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K4",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K2",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K3",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleTek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K2",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K1",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K2",
							Role:       spec.KeyRoleTek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K3",
							Role:       spec.KeyRoleKek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
						},
						{
							Kind:       "K4",
							Role:       spec.KeyRoleDek,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
							Kind:       "K0",
							Role:       spec.KeyRoleRoot,
							Algorithm:  cryptor.KeyAlgorithmAES256,
							LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
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
			keyToCheck model.KeyKind
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
							Algorithm: cryptor.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: cryptor.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleDek,
							Algorithm: cryptor.KeyAlgorithmAES256,
						},
					},
				},
				keyToCheck: "K1",
				expIsFound: true,
				expKeySpec: spec.KeySpec{
					Kind:      "K1",
					Role:      spec.KeyRoleKek,
					Algorithm: cryptor.KeyAlgorithmAES256,
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
							Algorithm: cryptor.KeyAlgorithmAES256,
						},
						{
							Kind:      "K1",
							Role:      spec.KeyRoleKek,
							Algorithm: cryptor.KeyAlgorithmAES256,
						},
						{
							Kind:      "K2",
							Role:      spec.KeyRoleDek,
							Algorithm: cryptor.KeyAlgorithmAES256,
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

	t.Run("IndexOf", func(t *testing.T) {
		hierarchy := &spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K3", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K4", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
			},
		}

		tts := []struct {
			name     string
			kind     model.KeyKind
			expIndex int
		}{
			{name: "found at index 0", kind: "K0", expIndex: 0},
			{name: "found at middle index", kind: "K2", expIndex: 2},
			{name: "found at last index", kind: "K4", expIndex: 4},
			{name: "not found", kind: "nonexistent", expIndex: -1},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				idx := hierarchy.IndexOf(tt.kind)
				assert.Equal(t, tt.expIndex, idx)
			})
		}
	})

	t.Run("KindsBetween", func(t *testing.T) {
		hierarchy := &spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K3", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K4", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
			},
		}

		t.Run("valid range returns correct sub-slice", func(t *testing.T) {
			specs, err := hierarchy.KindsBetween("K1", "K3")
			assert.NoError(t, err)
			assert.Len(t, specs, 3)
			assert.Equal(t, model.KeyKind("K1"), specs[0].Kind)
			assert.Equal(t, model.KeyKind("K2"), specs[1].Kind)
			assert.Equal(t, model.KeyKind("K3"), specs[2].Kind)
		})

		t.Run("single element range", func(t *testing.T) {
			specs, err := hierarchy.KindsBetween("K2", "K2")
			assert.NoError(t, err)
			assert.Len(t, specs, 1)
			assert.Equal(t, model.KeyKind("K2"), specs[0].Kind)
		})

		t.Run("full range returns entire slice", func(t *testing.T) {
			specs, err := hierarchy.KindsBetween("K0", "K4")
			assert.NoError(t, err)
			assert.Len(t, specs, 5)
		})

		t.Run("start kind not found", func(t *testing.T) {
			_, err := hierarchy.KindsBetween("nonexistent", "K3")
			assert.Error(t, err)
			assert.ErrorIs(t, err, spec.ErrKeyHierarchyKindNotFound)
		})

		t.Run("end kind not found", func(t *testing.T) {
			_, err := hierarchy.KindsBetween("K0", "nonexistent")
			assert.Error(t, err)
			assert.ErrorIs(t, err, spec.ErrKeyHierarchyKindNotFound)
		})

		t.Run("start after end", func(t *testing.T) {
			_, err := hierarchy.KindsBetween("K3", "K1")
			assert.Error(t, err)
			assert.ErrorIs(t, err, spec.ErrKeyHierarchyInvalidRange)
		})
	})
}
