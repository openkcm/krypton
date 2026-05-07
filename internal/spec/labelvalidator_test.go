package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func TestLabelValidatorValidate(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		// given
		tts := []struct {
			name   string
			subj   *spec.LabelValidator
			expErr error
		}{
			{
				name: "should not return error for nil validator",
				subj: nil,
			},
			{
				name: "should not return error for valid regex validator",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeRegex,
					Params: map[string]string{
						spec.ValidatorTypeRegexKey: "^[a-zA-Z0-9]+$",
					},
				},
			},
			{
				name: "should not return error for valid enum validator",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeEnum,
					Params: map[string]string{
						spec.ValidatorTypeEnumKey: "value1,value2,value3",
					},
				},
			},
			{
				name: "should return error for invalid validator type",
				subj: &spec.LabelValidator{
					Type: "invalid",
				},
				expErr: spec.ErrLabelValidatorInvalidType,
			},
			{
				name: "should return error for missing regex pattern",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeRegex,
				},
				expErr: spec.ErrLabelValidatorMissingRegexPattern,
			},
			{
				name: "should return error for invalid regex pattern",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeRegex,
					Params: map[string]string{
						spec.ValidatorTypeRegexKey: "^[a-zA-Z0-9+$",
					},
				},
				expErr: spec.ErrLabelValidatorInvalidRegexPattern,
			},
			{
				name: "should return error for missing enum values",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeEnum,
				},
				expErr: spec.ErrLabelValidatorMissingEnumValues,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err := spec.InitLabelValidator(tt.subj)

				// then
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})
}

func TestLabelValidatorValidateLabel(t *testing.T) {
	t.Run("ValidateLabel", func(t *testing.T) {
		// given
		tts := []struct {
			name   string
			subj   *spec.LabelValidator
			value  string
			expErr error
		}{
			{
				name: "should return error for invalid regex value",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeRegex,
					Params: map[string]string{
						spec.ValidatorTypeRegexKey: "^[a-zA-Z0-9]+$",
					},
				},
				value:  "invalid value!",
				expErr: spec.ErrLabelValidatorRegexFailed,
			},
			{
				name: "should return error for invalid regex pattern",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeRegex,
					Params: map[string]string{
						spec.ValidatorTypeRegexKey: "^[a-zA-Z0-9+$",
					},
				},
				value:  "validValue123",
				expErr: spec.ErrLabelValidatorInvalidRegexPattern,
			},
			{
				name: "should return nil for valid regex value",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeRegex,
					Params: map[string]string{
						spec.ValidatorTypeRegexKey: "^[a-zA-Z0-9]+$",
					},
				},
				value:  "validValue123",
				expErr: nil,
			},
			{
				name: "should return error for invalid enum value",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeEnum,
					Params: map[string]string{
						spec.ValidatorTypeEnumKey: "value1,value2,value3",
					},
				},
				value:  "value",
				expErr: spec.ErrLabelValidatorEnumFailed,
			},
			{
				name: "should return nil for valid enum value",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeEnum,
					Params: map[string]string{
						spec.ValidatorTypeEnumKey: "value1,value2,value3",
					},
				},
				value:  "value2",
				expErr: nil,
			},
			{
				name: "should handle enum values with surrounding whitespace",
				subj: &spec.LabelValidator{
					Type: spec.ValidatorTypeEnum,
					Params: map[string]string{
						spec.ValidatorTypeEnumKey: "value1, value2 , value3",
					},
				},
				value: "value2",
			},
			{
				name: "should return error for invalid validator type",
				subj: &spec.LabelValidator{
					Type: "invalid",
				},
				value:  "anyValue",
				expErr: spec.ErrLabelValidatorInvalidType,
			},
			{
				name:   "should return nil for nil validator",
				subj:   nil,
				value:  "anyValue",
				expErr: nil,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err := spec.ValidateLabelValidator(tt.subj, tt.value)

				// then
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})
}
