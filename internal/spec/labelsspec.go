package spec

import (
	"errors"
	"fmt"
	"maps"

	"github.com/openkcm/krypton/pkg/model"
)

// LabelsSpec defines validation requirements for labels attached to topology segments.
// It enforces both structural constraints (required vs optional) and value constraints
// (regex patterns or enum values).
//
// When AllowUserLabels is true, labels beyond the declared requirements are permitted
// and an empty Requirements map is considered valid. When false (the default), only
// labels that match a declared requirement are accepted and at least one requirement
// must be defined.
//
// Example YAML configuration:
//
//	allow_user_labels: false
//	requirements:
//	  env:
//	    is_required: true
//	    validator:
//	      type: regex
//	      params:
//	        pattern: "^(production|staging|development)$"
//	  region:
//	    is_required: false
//	    validator:
//	      type: enum
//	      params:
//	        values: "us-east-1,us-west-2,eu-west-1"
type LabelsSpec struct {
	Requirements    map[string]LabelRequirement `yaml:"requirements,omitempty"`
	AllowUserLabels bool                        `yaml:"allow_user_labels"`
}

var (
	ErrLabelsValidationFailed     = errors.New("labels validation failed")
	ErrLabelsSpecRequirementEmpty = errors.New("label spec requirement is empty")
)

// Validate validates actual label values against the spec requirements.
// It checks that:
//   - All required labels are present
//   - All label values pass their validator constraints
//   - No unexpected labels are present when AllowUserLabels is false (strict validation)
//
// When AllowUserLabels is true, labels that do not match any requirement are
// silently accepted without validation.
func (ls *LabelsSpec) Validate(l model.Labels) error {
	for reqName, req := range ls.Requirements {
		value, exists := l[reqName]
		if req.IsRequired && !exists {
			return fmt.Errorf("%w: missing required label '%s'", ErrLabelsValidationFailed, reqName)
		}
		if !exists {
			continue
		}

		validator := req.Validator
		if validator != nil {
			if err := validator.validate(value); err != nil {
				return fmt.Errorf("label '%s': %w", reqName, err)
			}
		}
	}

	if !ls.AllowUserLabels {
		for lbName := range l {
			if _, exists := ls.Requirements[lbName]; !exists {
				return fmt.Errorf("%w: unexpected label '%s'", ErrLabelsValidationFailed, lbName)
			}
		}
	}

	return nil
}

// Merge merges another LabelsSpec into the current one.
func (ls *LabelsSpec) Merge(src LabelsSpec) {
	if ls.Requirements == nil {
		ls.Requirements = make(map[string]LabelRequirement)
	}
	maps.Copy(ls.Requirements, src.Requirements)
	ls.AllowUserLabels = src.AllowUserLabels
}

// init performs initialization and validation of the LabelsSpec.
// It checks that if AllowUserLabels is false, at least one requirement is defined.
// It also validates each individual LabelRequirement.
func (ls *LabelsSpec) init() error {
	if !ls.AllowUserLabels && len(ls.Requirements) == 0 {
		return fmt.Errorf("%w: no label requirements defined", ErrLabelsSpecRequirementEmpty)
	}
	for _, req := range ls.Requirements {
		if err := req.init(); err != nil {
			return err
		}
	}
	return nil
}
