package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func TestLabelRequirementValidate(t *testing.T) {
	t.Run("Validate", func(t *testing.T) {
		tts := []struct {
			name   string
			subj   *spec.LabelRequirement
			expErr error
		}{
			{
				name: "should not return error for nil validator",
				subj: &spec.LabelRequirement{
					IsRequired: true,
					Validator:  nil,
				},
			},
			{
				name: "should return error for invalid regex validator",
				subj: &spec.LabelRequirement{
					IsRequired: true,
					Validator: &spec.LabelValidator{
						Type: "invalid",
					},
				},
				expErr: spec.ErrLabelValidatorInvalidType,
			},
			{
				name: "should not return error for valid regex validator",
				subj: &spec.LabelRequirement{
					IsRequired: true,
					Validator: &spec.LabelValidator{
						Type: spec.ValidatorTypeRegex,
						Params: map[string]string{
							spec.ValidatorTypeRegexKey: "^[a-zA-Z0-9]+$",
						},
					},
				},
				expErr: nil,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				err := spec.InitLabelRequirement(tt.subj)

				// then
				assert.ErrorIs(t, err, tt.expErr)
			})
		}
	})
}
