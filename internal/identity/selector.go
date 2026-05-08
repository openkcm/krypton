package identity

import (
	"encoding/json"
	"errors"
	"strings"
)

var (
	// ErrInvalidSelectorScheme is returned when parsing a selector with wrong scheme.
	ErrInvalidSelectorScheme = errors.New("invalid selector scheme: must be 'kryptonid'")

	// ErrInvalidSelectorPath is returned when the selector path is malformed.
	ErrInvalidSelectorPath = errors.New("invalid selector path: must have type/name pairs, optionally ending with **")
)

// Selector matches Identity values using wildcards.
type Selector struct {
	Domain Domain
	Fields []FieldSelector
}

// Matches checks if a concrete Identity matches this selector.
// Domain is always matched literally.
// "*" in a field's Name matches any name for that type.
// "**" as a trailing type matches zero or more remaining fields of any type.
// Selector and value must have the same field count unless selector ends with "**".
func (s *Selector) Matches(id Identity) bool {
	if s.Domain != id.Domain {
		return false
	}

	for i, fs := range s.Fields {
		if fs.Type == "**" {
			return true
		}
		if i >= len(id.Fields) {
			return false
		}
		if !fs.Matches(id.Fields[i]) {
			return false
		}
	}

	return len(s.Fields) == len(id.Fields)
}

// String returns the kryptonid:// URI representation of the selector.
func (s *Selector) String() string {
	var b strings.Builder

	b.WriteString(Scheme)
	b.WriteString("://")
	b.WriteString(s.Domain.String())

	for _, f := range s.Fields {
		b.WriteByte('/')
		if f.Type == "**" {
			b.WriteString("**")
			break
		}
		b.WriteString(f.Type)
		b.WriteByte('/')
		b.WriteString(f.Name)
	}

	return b.String()
}

// MarshalJSON serializes Selector as a URI string.
func (s *Selector) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON deserializes Selector from a URI string.
func (s *Selector) UnmarshalJSON(data []byte) error {
	var uri string
	if err := json.Unmarshal(data, &uri); err != nil {
		return err
	}

	parsed, err := ParseSelector(uri)
	if err != nil {
		return err
	}

	*s = parsed
	return nil
}

// ParseSelector parses a kryptonid:// selector string into a Selector.
// Returns an error if the scheme is wrong, domain is empty or invalid,
// or the path has an odd number of fields without a trailing "**".
func ParseSelector(raw string) (Selector, error) {
	after, found := strings.CutPrefix(raw, Scheme+"://")
	if !found {
		return Selector{}, ErrInvalidSelectorScheme
	}

	d, path, _ := strings.Cut(after, "/")
	if err := Domain(d).Validate(); err != nil {
		return Selector{}, err
	}

	if path == "" {
		return Selector{}, ErrInvalidSelectorPath
	}

	parts := strings.Split(path, "/")
	var fields []FieldSelector

	for len(parts) > 0 {
		if parts[0] == "**" {
			fields = append(fields, FieldSelector{Type: "**"})
			break
		}

		if len(parts) < 2 {
			return Selector{}, ErrInvalidSelectorPath
		}

		fields = append(fields, FieldSelector{Type: parts[0], Name: parts[1]})
		parts = parts[2:]
	}

	return Selector{
		Domain: Domain(d),
		Fields: fields,
	}, nil
}

// FieldSelector represents a type/name pair in an identity selector.
// Name can be "*" to match any name.
// Type can be "**" to match zero or more trailing fields of any type.
type FieldSelector struct {
	Type string
	Name string
}

// Matches checks if this field selector matches a concrete field.
// Type must match exactly. Name must match exactly or selector name is "*".
func (fs FieldSelector) Matches(f Field) bool {
	if fs.Type != f.Type {
		return false
	}
	if fs.Name == "*" {
		return true
	}
	return fs.Name == f.Name
}

// MatchesAny checks if the identity matches any of the selectors.
func MatchesAny(ss []Selector, i Identity) bool {
	for _, s := range ss {
		if s.Matches(i) {
			return true
		}
	}
	return false
}
