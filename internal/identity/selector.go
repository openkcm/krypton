package identity

import (
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidSelectorPath = errors.New("invalid selector path")

const (
	// AnyName matches any single name in a field position.
	AnyName = "*"

	// AnyRemaining matches all remaining fields from its position onward.
	AnyRemaining = "**"
)

type (
	// FieldSelector matches a single Field.
	FieldSelector struct {
		Type string
		Name string
	}

	// Selector matches identities using a kryptonid:// URI with support for wildcards:
	//
	//   - kryptonid://domain/type/name              exact field match, no further fields
	//   - kryptonid://domain/type/*                 any name for the type, no further fields
	//   - kryptonid://domain/type/*/othertype/name  any name for first type, exact second field
	//   - kryptonid://domain/type/**                type must match, any name and any further fields
	//   - kryptonid://domain/**                     any identity in the domain
	//
	// Matching is positional and ** is always terminal.
	Selector struct {
		Domain Domain
		Fields []FieldSelector
	}
)

// Matches reports whether the field selector matches the given field.
func (fs FieldSelector) Matches(f Field) bool {
	if fs.Type == AnyRemaining {
		return true
	}
	if fs.Type != f.Type {
		return false
	}
	if fs.Name == AnyName || fs.Name == AnyRemaining {
		return true
	}
	return fs.Name == f.Name
}

// Validate validates that the field selector has valid type and name patterns.
func (fs FieldSelector) Validate() error {
	if fs.Type == AnyRemaining {
		return nil
	}
	if fs.Type == "" {
		return ErrEmptyField
	}
	if strings.ContainsAny(fs.Type, invalidChars) {
		return ErrInvalidCharacters
	}

	if fs.Name == AnyName || fs.Name == AnyRemaining {
		return nil
	}
	if fs.Name == "" {
		return ErrEmptyField
	}
	if strings.ContainsAny(fs.Name, invalidChars) {
		return ErrInvalidCharacters
	}

	return nil
}

// Matches reports whether the selector matches the given identity.
func (s Selector) Matches(id Identity) bool {
	if s.Domain != id.Domain {
		return false
	}

	for i, fs := range s.Fields {
		if fs.Type == AnyRemaining {
			return true
		}
		if i >= len(id.Fields) || !fs.Matches(id.Fields[i]) {
			return false
		}
		if fs.Name == AnyRemaining {
			return true
		}
	}

	return len(id.Fields) == len(s.Fields)
}

// String returns the kryptonid:// pattern string representation.
func (s Selector) String() string {
	var b strings.Builder

	b.WriteString(Scheme)
	b.WriteString("://")
	b.WriteString(string(s.Domain))

	for _, fs := range s.Fields {
		b.WriteByte('/')
		b.WriteString(fs.Type)
		if fs.Type == AnyRemaining {
			break
		}
		b.WriteByte('/')
		b.WriteString(fs.Name)
	}

	return b.String()
}

// ParseSelector parses a kryptonid:// pattern string into a Selector.
// Returns an error if the scheme is wrong, the domain is invalid,
// or the path contains invalid or incomplete field patterns.
//
// Example pattern: kryptonid://acme-corp/node/**
func ParseSelector(raw string) (Selector, error) {
	after, found := strings.CutPrefix(raw, Scheme+"://")
	if !found {
		return Selector{}, ErrInvalidScheme
	}

	d, path, _ := strings.Cut(after, "/")
	if err := Domain(d).Validate(); err != nil {
		return Selector{}, err
	}

	fields, err := parseFields(path)
	if err != nil {
		return Selector{}, err
	}

	return Selector{
		Domain: Domain(d),
		Fields: fields,
	}, nil
}

func parseFields(path string) ([]FieldSelector, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: cannot be empty", ErrInvalidSelectorPath)
	}

	parts := strings.Split(path, "/")

	for i, p := range parts {
		if p == AnyRemaining && i != len(parts)-1 {
			return nil, fmt.Errorf("%w: ** must be the last segment", ErrInvalidSelectorPath)
		}
	}

	fields := make([]FieldSelector, 0, (len(parts)+1)/2)
	for len(parts) > 0 {
		if parts[0] == AnyRemaining {
			fields = append(fields, FieldSelector{Type: AnyRemaining})
			break
		}

		if len(parts) < 2 {
			return nil, fmt.Errorf("%w: incomplete type/name pair", ErrInvalidSelectorPath)
		}

		fs := FieldSelector{Type: parts[0], Name: parts[1]}
		if err := fs.Validate(); err != nil {
			return nil, err
		}

		fields = append(fields, fs)
		if fs.Name == AnyRemaining {
			break
		}
		parts = parts[2:]
	}

	return fields, nil
}
