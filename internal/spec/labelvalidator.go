package spec

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const (
	// ValidatorTypeRegex validates label values against a regular expression pattern
	ValidatorTypeRegex ValidatorType = "regex"
	// ValidatorTypeEnum validates label values against a comma-separated list of allowed values
	ValidatorTypeEnum ValidatorType = "enum"
	// ValidatorTypeRegexKey is the params key for regex pattern
	ValidatorTypeRegexKey string = "pattern"
	// ValidatorTypeEnumKey is the params key for enum values (comma-separated)
	ValidatorTypeEnumKey string = "values"
)

type (
	ValidatorType string

	// LabelValidator validates label values using either regex or enum constraints.
	// Validation configuration is lazily compiled and cached for thread-safe reuse.
	LabelValidator struct {
		Type   ValidatorType     `yaml:"type"`             // "regex" or "enum"
		Params map[string]string `yaml:"params,omitempty"` // Configuration parameters
		// Internal fields for caching compiled validators
		regex        *regexp.Regexp
		enums        map[string]struct{}
		validateOnce sync.Once
		validateErr  error
	}
)

var (
	ErrLabelValidatorInvalidType         = errors.New("invalid label validator type")
	ErrLabelValidatorMissingRegexPattern = errors.New("missing regex pattern for regex validator")
	ErrLabelValidatorInvalidRegexPattern = errors.New("invalid regex pattern")
	ErrLabelValidatorMissingEnumValues   = errors.New("missing enum values for enum validator")
	ErrLabelValidatorEnumFailed          = errors.New("enum validation failed")
	ErrLabelValidatorRegexFailed         = errors.New("regex validation failed")
)

// Validate checks the validator configuration and compiles patterns (lazily, once).
// Returns an error if the validator type or parameters are invalid.
func (lv *LabelValidator) Validate() error {
	if lv == nil {
		return nil
	}

	lv.validateOnce.Do(func() {
		switch lv.Type {
		case ValidatorTypeRegex:
			pattern, ok := lv.Params[ValidatorTypeRegexKey]
			if !ok {
				lv.validateErr = ErrLabelValidatorMissingRegexPattern
				return
			}
			lv.regex, lv.validateErr = regexp.Compile(pattern)
			if lv.validateErr != nil {
				lv.validateErr = fmt.Errorf("%w: invalid regex pattern '%s'", ErrLabelValidatorInvalidRegexPattern, pattern)
			}
		case ValidatorTypeEnum:
			valueStr, ok := lv.Params[ValidatorTypeEnumKey]
			if !ok {
				lv.validateErr = ErrLabelValidatorMissingEnumValues
				return
			}
			values := strings.Split(valueStr, ",")
			lv.enums = make(map[string]struct{}, len(values))
			for _, v := range values {
				lv.enums[strings.TrimSpace(v)] = struct{}{}
			}
		default:
			lv.validateErr = ErrLabelValidatorInvalidType
		}
	})

	return lv.validateErr
}

// ValidateValue validates a label value against this validator's constraints.
// The validator configuration is validated first if not already done.
func (lv *LabelValidator) ValidateValue(value string) error {
	if lv == nil {
		return nil
	}
	if err := lv.Validate(); err != nil {
		return err
	}

	switch lv.Type {
	case ValidatorTypeRegex:
		return lv.validateRegex(value)
	case ValidatorTypeEnum:
		return lv.validateEnum(value)
	default:
		return fmt.Errorf("%w: %s", ErrLabelValidatorInvalidType, lv.Type)
	}
}

func (lv *LabelValidator) validateEnum(value string) error {
	if len(lv.enums) == 0 {
		return ErrLabelValidatorMissingEnumValues
	}
	_, exists := lv.enums[value]
	if !exists {
		return fmt.Errorf("%w: value '%s' is not in enum values", ErrLabelValidatorEnumFailed, value)
	}
	return nil
}

func (lv *LabelValidator) validateRegex(value string) error {
	if lv.regex == nil {
		return ErrLabelValidatorMissingRegexPattern
	}
	if !lv.regex.MatchString(value) {
		pattern := lv.Params[ValidatorTypeRegexKey]
		return fmt.Errorf("%w: value '%s' does not match regex pattern '%s'", ErrLabelValidatorRegexFailed, value, pattern)
	}
	return nil
}
