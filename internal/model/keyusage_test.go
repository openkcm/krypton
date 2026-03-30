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
}
