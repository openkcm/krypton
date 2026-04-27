package spec

// LabelRequirement defines whether a label is required and how to validate its value.
type LabelRequirement struct {
	IsRequired bool            `yaml:"isRequired"`          // If true, the label must be present
	Validator  *LabelValidator `yaml:"validator,omitempty"` // Optional value validator
}

// Validate checks that the requirement's validator configuration is valid.
func (lr *LabelRequirement) Validate() error {
	if lr.Validator != nil {
		return lr.Validator.Validate()
	}
	return nil
}
