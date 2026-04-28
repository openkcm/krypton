package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
)

func TestLabelsSpecValidate(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		// given
		tts := []struct {
			name   string
			subj   spec.LabelsSpec
			expErr error
		}{
			{
				name: "should return error for label spec with empty requirements and allowUserLabels is false",
				subj: spec.LabelsSpec{
					Requirements: map[string]spec.LabelRequirement{},
				},
				expErr: spec.ErrLabelsSpecRequirementEmpty,
			},
			{
				name: "should return error for label spec with nil requirements and allowUserLabels is false",
				subj: spec.LabelsSpec{
					Requirements: nil,
				},
				expErr: spec.ErrLabelsSpecRequirementEmpty,
			},
			{
				name: "should return nil for label spec with no requirements but allowUserLabels is true",
				subj: spec.LabelsSpec{
					AllowUserLabels: true,
					Requirements:    map[string]spec.LabelRequirement{},
				},
				expErr: nil,
			},
			{
				name: "should return error for invalid validator even when allowUserLabels is true",
				subj: spec.LabelsSpec{
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
				subj: spec.LabelsSpec{
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
				subj:   spec.LabelsSpec{},
				expErr: spec.ErrLabelsSpecRequirementEmpty,
			},
			{
				name: "should return nil for valid label spec",
				subj: spec.LabelsSpec{
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
				subj: spec.LabelsSpec{
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
				subj: spec.LabelsSpec{
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
				err := spec.InitLabelsSpec(&tt.subj)

				// then
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})
}

func TestLabelsSpecValidateLabels(t *testing.T) {
	t.Run("ValidateLabels", func(t *testing.T) {
		tts := []struct {
			name   string
			subj   spec.LabelsSpec
			labels model.Labels
			expErr error
		}{
			{
				name: "should return error for missing required label",
				subj: spec.LabelsSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator:  &spec.LabelValidator{},
						},
					},
				},
				labels: model.Labels{},
				expErr: spec.ErrLabelsValidationFailed,
			},
			{
				name: "should return nil for missing optional label",
				subj: spec.LabelsSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: false,
							Validator:  &spec.LabelValidator{},
						},
					},
				},
				labels: model.Labels{},
				expErr: nil,
			},
			{
				name: "should return nil if an unexpected label is present and allowUserLabels is true",
				subj: spec.LabelsSpec{
					AllowUserLabels: true,
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
						},
					},
				},
				labels: model.Labels{
					"version": "1.0",
					"env":     "production",
				},
			},
			{
				name: "should return error if an unexpected label is present and allowUserLabels is false",
				subj: spec.LabelsSpec{
					AllowUserLabels: false,
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
						},
					},
				},
				labels: model.Labels{
					"version": "1.0",
					"env":     "production",
				},
				expErr: spec.ErrLabelsValidationFailed,
			},
			{
				name: "should return error if the regex validation fails",
				subj: spec.LabelsSpec{
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
				labels: model.Labels{
					"env": "invalid_env",
				},
				expErr: spec.ErrLabelValidatorRegexFailed,
			},
			{
				name: "should return nil if the regex validation passes",
				subj: spec.LabelsSpec{
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
				labels: model.Labels{
					"env": "production",
				},
				expErr: nil,
			},
			{
				name: "should return error for invalid regex pattern in validator",
				subj: spec.LabelsSpec{
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
				labels: model.Labels{
					"env": "production",
				},
				expErr: spec.ErrLabelValidatorInvalidRegexPattern,
			},
			{
				name: "should return error if enum validation fails",
				subj: spec.LabelsSpec{
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
				labels: model.Labels{
					"env": "invalid_env",
				},
				expErr: spec.ErrLabelValidatorEnumFailed,
			},
			{
				name: "should return nil if enum validation succeeds",
				subj: spec.LabelsSpec{
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
				labels: model.Labels{
					"env": "staging",
				},
			},
			{
				name: "should return nil for valid labels with multiple requirements",
				subj: spec.LabelsSpec{
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
				labels: model.Labels{
					"env":    "production",
					"region": "us-east-1",
				},
				expErr: nil,
			},
			{
				name: "should return nil for valid labels",
				subj: spec.LabelsSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
						},
					},
				},
				labels: model.Labels{
					"env": "production",
				},
				expErr: nil,
			},
			{
				name: "should return error for nil labels when required label exists",
				subj: spec.LabelsSpec{
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
				subj: spec.LabelsSpec{
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
				err := tt.subj.Validate(tt.labels)

				// then
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})
}
