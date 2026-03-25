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
					Keys: []model.KeySpec{
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
					Name: "production-hierarchy",
					Keys: []model.KeySpec{},
				},
				expErr: model.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "should return error if keys list is nil",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: nil,
				},
				expErr: model.ErrKeyHierarchyKeysListEmpty,
			},
			{
				name: "should return error if first key does not have role 'root'",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
				name: "should return error if there are duplicate key kinds",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
					Keys: []model.KeySpec{
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
					Keys: []model.KeySpec{
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
					Keys: []model.KeySpec{
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
					Keys: []model.KeySpec{
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
				expErr: model.ErrKeyHierarchyIntermediateKeyNotKek,
			},
			{
				name: "should return error if there is a non-kek key in the middle of the hierarchy",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
				expErr: model.ErrKeyHierarchyIntermediateKeyNotKek,
			},
			{
				name: "should return nil if the hierarchy has root and dek keys",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
					Keys: []model.KeySpec{
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
				name: "should return nil if the hierarchy has only a root key",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
}

func TestHas(t *testing.T) {
	tts := []struct {
		name  string
		subj  model.KeyUsage
		input model.KeyUsage
		expOk bool
	}{
		{
			name:  "should return true if the subject has only 'encrypt' flag",
			subj:  model.KeyUsageEncrypt,
			input: model.KeyUsageEncrypt,
			expOk: true,
		},
		{
			name:  "should return true if the subject has only 'decrypt' flag",
			subj:  model.KeyUsageDecrypt,
			input: model.KeyUsageDecrypt,
			expOk: true,
		},
		{
			name:  "should return true if the subject has only 'wrap' flag",
			subj:  model.KeyUsageWrap,
			input: model.KeyUsageWrap,
			expOk: true,
		},
		{
			name:  "should return true if the subject has only 'unwrap' flag",
			subj:  model.KeyUsageUnwrap,
			input: model.KeyUsageUnwrap,
			expOk: true,
		},
		{
			name:  "should return true if the subject has multiple flags and the input matches all of them",
			subj:  model.KeyUsageEncrypt | model.KeyUsageDecrypt | model.KeyUsageWrap,
			input: model.KeyUsageEncrypt | model.KeyUsageDecrypt | model.KeyUsageWrap,
			expOk: true,
		},
		{
			name:  "should return true if the subject has multiple flags and the input is a subset of them",
			subj:  model.KeyUsageEncrypt | model.KeyUsageDecrypt | model.KeyUsageWrap,
			input: model.KeyUsageEncrypt | model.KeyUsageDecrypt,
			expOk: true,
		},
		{
			name:  "should return false if the input contains a flag that is set and a flag that is not set in the subject",
			subj:  model.KeyUsageEncrypt | model.KeyUsageDecrypt | model.KeyUsageWrap,
			input: model.KeyUsageDecrypt | model.KeyUsageUnwrap,
			expOk: false,
		},
		{
			name:  "should return false if the subject contains only one of the multiple flags in the input",
			subj:  model.KeyUsageEncrypt,
			input: model.KeyUsageEncrypt | model.KeyUsageWrap,
			expOk: false,
		},
		{
			name:  "should return false if the input is zero",
			subj:  model.KeyUsageEncrypt | model.KeyUsageDecrypt | model.KeyUsageWrap,
			input: 0,
			expOk: false,
		},
		{
			name:  "should return false if the input is not in the subject",
			subj:  model.KeyUsageEncrypt | model.KeyUsageDecrypt,
			input: model.KeyUsage(64),
			expOk: false,
		},
		{
			name:  "should return false if the subject is zero",
			subj:  model.KeyUsage(0),
			input: model.KeyUsageEncrypt,
			expOk: false,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			ok := tt.subj.Has(tt.input)

			// then
			assert.Equal(t, tt.expOk, ok)
		})
	}
}

func TestKeyUsage(t *testing.T) {
	t.Run("Usage", func(t *testing.T) {
		// given
		tts := []struct {
			name         string
			input        *model.KeyHierarchy
			keyToCheck   model.KeyKind
			expIsFound   bool
			expIsEncrypt bool
			expIsDecrypt bool
			expIsWrap    bool
			expIsUnwrap  bool
		}{
			{
				name: "should return encrypt and decrypt if the key kind belongs to a single 'root' key hierarchy",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
						{
							Kind:      "K0",
							Role:      model.KeyRoleRoot,
							Algorithm: model.KeyAlgorithmAES256,
						},
					},
				},
				keyToCheck:   "K0",
				expIsFound:   true,
				expIsEncrypt: true,
				expIsDecrypt: true,
			},
			{
				name: "should return wrap and unwrap if the key kind belongs to a 'kek' key in a multi-key hierarchy",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
				keyToCheck:  "K1",
				expIsFound:  true,
				expIsWrap:   true,
				expIsUnwrap: true,
			},
			{
				name: "should return encrypt and decrypt if the key kind belongs to a 'dek' key in a multi-key hierarchy",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
				keyToCheck:   "K2",
				expIsFound:   true,
				expIsEncrypt: true,
				expIsDecrypt: true,
			},
			{
				name: "should return wrap and unwrap if the key kind belongs to a 'root' key in a multi-key hierarchy",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
				keyToCheck:  "K0",
				expIsFound:  true,
				expIsWrap:   true,
				expIsUnwrap: true,
			},
			{
				name: "should return zero usage and false if the key kind does not exist in the hierarchy",
				input: &model.KeyHierarchy{
					Name: "production-hierarchy",
					Keys: []model.KeySpec{
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
				keyToCheck:   "non-existent-key",
				expIsFound:   false,
				expIsEncrypt: false,
				expIsDecrypt: false,
				expIsWrap:    false,
				expIsUnwrap:  false,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				subj, ok := tt.input.Usage(tt.keyToCheck)

				// then
				assert.Equal(t, tt.expIsFound, ok)

				ok = subj.Has(model.KeyUsageEncrypt)
				assert.Equal(t, tt.expIsEncrypt, ok)

				ok = subj.Has(model.KeyUsageDecrypt)
				assert.Equal(t, tt.expIsDecrypt, ok)

				ok = subj.Has(model.KeyUsageWrap)
				assert.Equal(t, tt.expIsWrap, ok)

				ok = subj.Has(model.KeyUsageUnwrap)
				assert.Equal(t, tt.expIsUnwrap, ok)
			})
		}
	})
	t.Run("Usage should cache the usage for each key kind after the first call", func(t *testing.T) {
		// given
		hierarchy := &model.KeyHierarchy{
			Name: "production-hierarchy",
			Keys: []model.KeySpec{
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
		}

		err := hierarchy.Validate()
		assert.NoError(t, err)

		keyToCheck := model.KeyKind("K1")

		// when
		subj, ok := hierarchy.Usage(keyToCheck)

		// then
		assert.True(t, ok)
		assert.True(t, subj.Has(model.KeyUsageWrap))
		assert.True(t, subj.Has(model.KeyUsageUnwrap))

		// when (mutate the hierarchy after the first call to Usage)
		hierarchy.Keys[1].Role = model.KeyRoleDek

		// when (call Usage again to check if the usage is cached)
		subj, ok = hierarchy.Usage(keyToCheck)

		// then
		assert.True(t, ok)
		assert.True(t, subj.Has(model.KeyUsageWrap))
		assert.True(t, subj.Has(model.KeyUsageUnwrap))
	})
}

func TestKeySpec(t *testing.T) {
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
}
