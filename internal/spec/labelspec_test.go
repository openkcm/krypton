package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func TestLabelSpecValidate(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		// given
		tts := []struct {
			name   string
			subj   spec.LabelSpec
			expErr error
		}{
			{
				name: "should return error for label spec with empty requirements and allowUserLabels is false",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{},
				},
				expErr: spec.ErrLabelsSpecRequirementEmpty,
			},
			{
				name: "should return error for label spec with nil requirements and allowUserLabels is false",
				subj: spec.LabelSpec{
					Requirements: nil,
				},
				expErr: spec.ErrLabelsSpecRequirementEmpty,
			},
			{
				name: "should return nil for label spec with no requirements but allowUserLabels is true",
				subj: spec.LabelSpec{
					AllowUserLabels: true,
					Requirements:    map[string]spec.LabelRequirement{},
				},
				expErr: nil,
			},
			{
				name: "should return error for invalid validator even when allowUserLabels is true",
				subj: spec.LabelSpec{
					AllowUserLabels: true,
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: "invalid",
							},
						},
					},
				},
				expErr: spec.ErrLabelValidatorInvalidType,
			},
			{
				name: "should return error for invalid validator type in label requirement",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"": {
							IsRequired: false,
							Validator: &spec.LabelValidator{
								Type: "invalid",
							},
						},
					},
				},
				expErr: spec.ErrLabelValidatorInvalidType,
			},
			{
				name:   "should return error for empty label spec",
				subj:   spec.LabelSpec{},
				expErr: spec.ErrLabelsSpecRequirementEmpty,
			},
			{
				name: "should return nil for valid label spec",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeEnum,
								Params: map[string]string{
									spec.ValidatorTypeEnumKey: "production,staging,development",
								},
							},
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return nil for label spec with no validators",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
						},
						"region": {
							IsRequired: false,
						},
					},
				},
				expErr: nil,
			},
			{
				name: "should return error for label spec with invalid regex pattern in validator",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeRegex,
								Params: map[string]string{
									spec.ValidatorTypeRegexKey: "^(production|staging|development$",
								},
							},
						},
					},
				},
				expErr: spec.ErrLabelValidatorInvalidRegexPattern,
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err := tt.subj.Validate()

				// then
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})
}

func TestLabelSpecValidateLabels(t *testing.T) {
	t.Run("ValidateLabels", func(t *testing.T) {
		tts := []struct {
			name   string
			subj   spec.LabelSpec
			labels spec.Labels
			expErr error
		}{
			{
				name: "should return error for missing required label",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator:  &spec.LabelValidator{},
						},
					},
				},
				labels: spec.Labels{},
				expErr: spec.ErrLabelsValidationFailed,
			},
			{
				name: "should return nil for missing optional label",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: false,
							Validator:  &spec.LabelValidator{},
						},
					},
				},
				labels: spec.Labels{},
				expErr: nil,
			},
			{
				name: "should return nil if an unexpected label is present and allowUserLabels is true",
				subj: spec.LabelSpec{
					AllowUserLabels: true,
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
						},
					},
				},
				labels: spec.Labels{
					"version": "1.0",
					"env":     "production",
				},
			},
			{
				name: "should return error if an unexpected label is present and allowUserLabels is false",
				subj: spec.LabelSpec{
					AllowUserLabels: false,
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
						},
					},
				},
				labels: spec.Labels{
					"version": "1.0",
					"env":     "production",
				},
				expErr: spec.ErrLabelsValidationFailed,
			},
			{
				name: "should return error if the regex validation fails",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeRegex,
								Params: map[string]string{
									spec.ValidatorTypeRegexKey: "^(production|staging|development)$",
								},
							},
						},
					},
				},
				labels: spec.Labels{
					"env": "invalid_env",
				},
				expErr: spec.ErrLabelValidatorRegexFailed,
			},
			{
				name: "should return nil if the regex validation passes",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeRegex,
								Params: map[string]string{
									spec.ValidatorTypeRegexKey: "^(production|staging|development)$",
								},
							},
						},
					},
				},
				labels: spec.Labels{
					"env": "production",
				},
				expErr: nil,
			},
			{
				name: "should return error for invalid regex pattern in validator",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeRegex,
								Params: map[string]string{
									spec.ValidatorTypeRegexKey: "^(production|staging|development$",
								},
							},
						},
					},
				},
				labels: spec.Labels{
					"env": "production",
				},
				expErr: spec.ErrLabelValidatorInvalidRegexPattern,
			},
			{
				name: "should return error if enum validation fails",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeEnum,
								Params: map[string]string{
									spec.ValidatorTypeEnumKey: "production,staging,development",
								},
							},
						},
					},
				},
				labels: spec.Labels{
					"env": "invalid_env",
				},
				expErr: spec.ErrLabelValidatorEnumFailed,
			},
			{
				name: "should return nil if enum validation succeeds",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeEnum,
								Params: map[string]string{
									spec.ValidatorTypeEnumKey: "production,staging,development",
								},
							},
						},
					},
				},
				labels: spec.Labels{
					"env": "staging",
				},
			},
			{
				name: "should return nil for valid labels with multiple requirements",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeEnum,
								Params: map[string]string{
									spec.ValidatorTypeEnumKey: "production,staging",
								},
							},
						},
						"region": {
							IsRequired: false,
							Validator: &spec.LabelValidator{
								Type: spec.ValidatorTypeRegex,
								Params: map[string]string{
									spec.ValidatorTypeRegexKey: "^[a-z]+-[a-z]+-[0-9]+$",
								},
							},
						},
					},
				},
				labels: spec.Labels{
					"env":    "production",
					"region": "us-east-1",
				},
				expErr: nil,
			},
			{
				name: "should return nil for valid labels",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
						},
					},
				},
				labels: spec.Labels{
					"env": "production",
				},
				expErr: nil,
			},
			{
				name: "should return error for nil labels when required label exists",
				subj: spec.LabelSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
						},
					},
				},
				labels: nil,
				expErr: spec.ErrLabelsValidationFailed,
			},
			{
				name: "should return nil for nil labels when no required labels exist",
				subj: spec.LabelSpec{
					AllowUserLabels: true,
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: false,
						},
					},
				},
				labels: nil,
				expErr: nil,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err := tt.subj.ValidateLabels(tt.labels)

				// then
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})
}
