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

// init initializes the validator by compiling regex patterns or parsing enum values.
func (lv *LabelValidator) init() error {
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

// validate validates the given value against the validator's constraints.
// It returns an error if the value does not satisfy the constraints or if the validator is misconfigured.
func (lv *LabelValidator) validate(value string) error {
	if lv == nil {
		return nil
	}
	if err := lv.init(); err != nil {
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

// validateEnum checks if the value is one of the allowed enum values.
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

// validateRegex checks if the value matches the compiled regex pattern.
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
