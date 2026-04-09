package models_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/models"
)

func TestKeyUsage(t *testing.T) {
	t.Run("Has", func(t *testing.T) {
		tts := []struct {
			name  string
			subj  models.KeyUsage
			input models.KeyUsage
			expOk bool
		}{
			{
				name:  "should return true if the subject has only 'encrypt' flag",
				subj:  models.KeyUsageEncrypt,
				input: models.KeyUsageEncrypt,
				expOk: true,
			},
			{
				name:  "should return true if the subject has only 'decrypt' flag",
				subj:  models.KeyUsageDecrypt,
				input: models.KeyUsageDecrypt,
				expOk: true,
			},
			{
				name:  "should return true if the subject has only 'wrap' flag",
				subj:  models.KeyUsageWrap,
				input: models.KeyUsageWrap,
				expOk: true,
			},
			{
				name:  "should return true if the subject has only 'unwrap' flag",
				subj:  models.KeyUsageUnwrap,
				input: models.KeyUsageUnwrap,
				expOk: true,
			},
			{
				name:  "should return true if the subject has multiple flags and the input matches all of them",
				subj:  models.KeyUsageEncrypt | models.KeyUsageDecrypt | models.KeyUsageWrap,
				input: models.KeyUsageEncrypt | models.KeyUsageDecrypt | models.KeyUsageWrap,
				expOk: true,
			},
			{
				name:  "should return true if the subject has multiple flags and the input is a subset of them",
				subj:  models.KeyUsageEncrypt | models.KeyUsageDecrypt | models.KeyUsageWrap,
				input: models.KeyUsageEncrypt | models.KeyUsageDecrypt,
				expOk: true,
			},
			{
				name:  "should return false if the input contains a flag that is set and a flag that is not set in the subject",
				subj:  models.KeyUsageEncrypt | models.KeyUsageDecrypt | models.KeyUsageWrap,
				input: models.KeyUsageDecrypt | models.KeyUsageUnwrap,
				expOk: false,
			},
			{
				name:  "should return false if the subject contains only one of the multiple flags in the input",
				subj:  models.KeyUsageEncrypt,
				input: models.KeyUsageEncrypt | models.KeyUsageWrap,
				expOk: false,
			},
			{
				name:  "should return false if the input is zero",
				subj:  models.KeyUsageEncrypt | models.KeyUsageDecrypt | models.KeyUsageWrap,
				input: 0,
				expOk: false,
			},
			{
				name:  "should return false if the input is not in the subject",
				subj:  models.KeyUsageEncrypt | models.KeyUsageDecrypt,
				input: models.KeyUsage(64),
				expOk: false,
			},
			{
				name:  "should return false if the subject is zero",
				subj:  models.KeyUsage(0),
				input: models.KeyUsageEncrypt,
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
			input models.KeyUsage
			exp   string
		}{
			{
				name:  "should return 'none' if no flags are set",
				input: models.KeyUsageNone,
				exp:   "none",
			},
			{
				name:  "should return 'encrypt' if only the encrypt flag is set",
				input: models.KeyUsageEncrypt,
				exp:   "encrypt",
			},
			{
				name:  "should return 'decrypt' if only the decrypt flag is set",
				input: models.KeyUsageDecrypt,
				exp:   "decrypt",
			},
			{
				name:  "should return 'wrap' if only the wrap flag is set",
				input: models.KeyUsageWrap,
				exp:   "wrap",
			},
			{
				name:  "should return 'unwrap' if only the unwrap flag is set",
				input: models.KeyUsageUnwrap,
				exp:   "unwrap",
			},
			{
				name:  "should return multiple flag names separated by '|' if multiple flags are set",
				input: models.KeyUsageEncrypt | models.KeyUsageDecrypt | models.KeyUsageWrap,
				exp:   "encrypt|decrypt|wrap",
			},
			{
				name:  "should return the valid flag names followed by unknown flags if there are extra flags set",
				input: models.KeyUsage(64),
				exp:   "unknown(64)",
			},
			{
				name:  "should return the valid flag names followed by unknown flags if there are valid and extra flags set",
				input: models.KeyUsage(32) | models.KeyUsageEncrypt,
				exp:   "encrypt|unknown(32)",
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
		validUsages := models.ValidKeyUsages
		validUsageNames := models.ValidKeyUsageNames

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
