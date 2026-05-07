package spec

// LabelRequirement defines whether a label is required and how to validate its value.
type LabelRequirement struct {
	IsRequired bool            `yaml:"is_required"`         // If true, the label must be present
	Validator  *LabelValidator `yaml:"validator,omitempty"` // Optional value validator
}

// init performs initialization and validation of the LabelRequirement.
func (lr *LabelRequirement) init() error {
	if lr.Validator != nil {
		return lr.Validator.init()
	}
	return nil
}
