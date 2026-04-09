package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func TestKeyUsage(t *testing.T) {
	t.Run("Has", func(t *testing.T) {
		tts := []struct {
			name  string
			subj  spec.KeyUsage
			input spec.KeyUsage
			expOk bool
		}{
			{
				name:  "should return true if the subject has only 'encrypt' flag",
				subj:  spec.KeyUsageEncrypt,
				input: spec.KeyUsageEncrypt,
				expOk: true,
			},
			{
				name:  "should return true if the subject has only 'decrypt' flag",
				subj:  spec.KeyUsageDecrypt,
				input: spec.KeyUsageDecrypt,
				expOk: true,
			},
			{
				name:  "should return true if the subject has only 'wrap' flag",
				subj:  spec.KeyUsageWrap,
				input: spec.KeyUsageWrap,
				expOk: true,
			},
			{
				name:  "should return true if the subject has only 'unwrap' flag",
				subj:  spec.KeyUsageUnwrap,
				input: spec.KeyUsageUnwrap,
				expOk: true,
			},
			{
				name:  "should return true if the subject has multiple flags and the input matches all of them",
				subj:  spec.KeyUsageEncrypt | spec.KeyUsageDecrypt | spec.KeyUsageWrap,
				input: spec.KeyUsageEncrypt | spec.KeyUsageDecrypt | spec.KeyUsageWrap,
				expOk: true,
			},
			{
				name:  "should return true if the subject has multiple flags and the input is a subset of them",
				subj:  spec.KeyUsageEncrypt | spec.KeyUsageDecrypt | spec.KeyUsageWrap,
				input: spec.KeyUsageEncrypt | spec.KeyUsageDecrypt,
				expOk: true,
			},
			{
				name:  "should return false if the input contains a flag that is set and a flag that is not set in the subject",
				subj:  spec.KeyUsageEncrypt | spec.KeyUsageDecrypt | spec.KeyUsageWrap,
				input: spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
				expOk: false,
			},
			{
				name:  "should return false if the subject contains only one of the multiple flags in the input",
				subj:  spec.KeyUsageEncrypt,
				input: spec.KeyUsageEncrypt | spec.KeyUsageWrap,
				expOk: false,
			},
			{
				name:  "should return false if the input is zero",
				subj:  spec.KeyUsageEncrypt | spec.KeyUsageDecrypt | spec.KeyUsageWrap,
				input: 0,
				expOk: false,
			},
			{
				name:  "should return false if the input is not in the subject",
				subj:  spec.KeyUsageEncrypt | spec.KeyUsageDecrypt,
				input: spec.KeyUsage(64),
				expOk: false,
			},
			{
				name:  "should return false if the subject is zero",
				subj:  spec.KeyUsage(0),
				input: spec.KeyUsageEncrypt,
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
			input spec.KeyUsage
			exp   string
		}{
			{
				name:  "should return 'none' if no flags are set",
				input: spec.KeyUsageNone,
				exp:   "none",
			},
			{
				name:  "should return 'encrypt' if only the encrypt flag is set",
				input: spec.KeyUsageEncrypt,
				exp:   "encrypt",
			},
			{
				name:  "should return 'decrypt' if only the decrypt flag is set",
				input: spec.KeyUsageDecrypt,
				exp:   "decrypt",
			},
			{
				name:  "should return 'wrap' if only the wrap flag is set",
				input: spec.KeyUsageWrap,
				exp:   "wrap",
			},
			{
				name:  "should return 'unwrap' if only the unwrap flag is set",
				input: spec.KeyUsageUnwrap,
				exp:   "unwrap",
			},
			{
				name:  "should return multiple flag names separated by '|' if multiple flags are set",
				input: spec.KeyUsageEncrypt | spec.KeyUsageDecrypt | spec.KeyUsageWrap,
				exp:   "encrypt|decrypt|wrap",
			},
			{
				name:  "should return the valid flag names followed by unknown flags if there are extra flags set",
				input: spec.KeyUsage(64),
				exp:   "unknown(64)",
			},
			{
				name:  "should return the valid flag names followed by unknown flags if there are valid and extra flags set",
				input: spec.KeyUsage(32) | spec.KeyUsageEncrypt,
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
		validUsages := spec.ValidKeyUsages
		validUsageNames := spec.ValidKeyUsageNames

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
