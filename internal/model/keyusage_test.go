package model_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/model"
)

func TestKeyUsage(t *testing.T) {
	t.Run("Has", func(t *testing.T) {
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
	})
	t.Run("String", func(t *testing.T) {
		tts := []struct {
			name  string
			input model.KeyUsage
			exp   string
		}{
			{
				name:  "should return 'none' if no flags are set",
				input: model.KeyUsageNone,
				exp:   "none",
			},
			{
				name:  "should return 'encrypt' if only the encrypt flag is set",
				input: model.KeyUsageEncrypt,
				exp:   "encrypt",
			},
			{
				name:  "should return 'decrypt' if only the decrypt flag is set",
				input: model.KeyUsageDecrypt,
				exp:   "decrypt",
			},
			{
				name:  "should return 'wrap' if only the wrap flag is set",
				input: model.KeyUsageWrap,
				exp:   "wrap",
			},
			{
				name:  "should return 'unwrap' if only the unwrap flag is	 set",
				input: model.KeyUsageUnwrap,
				exp:   "unwrap",
			},
			{
				name:  "should return multiple flag names separated by '|' if multiple flags are set",
				input: model.KeyUsageEncrypt | model.KeyUsageDecrypt | model.KeyUsageWrap,
				exp:   "encrypt|decrypt|wrap",
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				act := tt.input.String()

				// then
				assert.Equal(t, tt.exp, act)
			})
		}
	})

	t.Run("ValidKeyUsages", func(t *testing.T) {
		// when
		validUsages := model.ValidKeyUsages
		validUsageNames := model.ValidKeyUsageNames

		// then
		assert.Len(t, validUsages, 4, "number of valid usage names should be 4")
		assert.Len(t, validUsageNames, 4, "number of valid usage names should be 4")

		for _, usage := range validUsages {
			name, ok := validUsageNames[usage]
			assert.True(t, ok, "valid usage should have a corresponding name")
			assert.NotEmpty(t, name, "valid usage name should not be empty")
		}
	})
}
