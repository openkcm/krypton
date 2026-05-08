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
	ErrInvalidSelectorPath = errors.New("invalid selector path: must have kind/name pairs, optionally ending with **")
)

// Selector matches Identity values using wildcards.
type Selector struct {
	Domain   Domain
	Segments []SegmentSelector
}

// Matches checks if a concrete Identity matches this selector.
// Domain is always matched literally.
// "*" in a segment's Name matches any name for that kind.
// "**" as a trailing kind matches zero or more remaining segments of any kind.
// Selector and value must have the same segment count unless selector ends with "**".
func (s *Selector) Matches(id Identity) bool {
	if s.Domain != id.Domain {
		return false
	}

	for i, ss := range s.Segments {
		if ss.Kind == "**" {
			return true
		}
		if i >= len(id.Segments) {
			return false
		}
		if !ss.Matches(id.Segments[i]) {
			return false
		}
	}

	return len(s.Segments) == len(id.Segments)
}

// String returns the kryptonid:// URI representation of the selector.
func (s *Selector) String() string {
	var b strings.Builder

	b.WriteString(Scheme)
	b.WriteString("://")
	b.WriteString(s.Domain.String())

	for _, seg := range s.Segments {
		b.WriteByte('/')
		if seg.Kind == "**" {
			b.WriteString("**")
			break
		}
		b.WriteString(seg.Kind)
		b.WriteByte('/')
		b.WriteString(seg.Name)
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
// or the path has an odd number of segments without a trailing "**".
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
	var segments []SegmentSelector

	for len(parts) > 0 {
		if parts[0] == "**" {
			segments = append(segments, SegmentSelector{Kind: "**"})
			break
		}

		if len(parts) < 2 {
			return Selector{}, ErrInvalidSelectorPath
		}

		segments = append(segments, SegmentSelector{Kind: parts[0], Name: parts[1]})
		parts = parts[2:]
	}

	return Selector{
		Domain:   Domain(d),
		Segments: segments,
	}, nil
}

// SegmentSelector represents a kind/name pair in an identity selector.
// Name can be "*" to match any name.
// Kind can be "**" to match zero or more trailing segments of any kind.
type SegmentSelector struct {
	Kind string
	Name string
}

// Matches checks if this segment selector matches a concrete segment.
// Kind must match exactly. Name must match exactly or selector name is "*".
func (ss SegmentSelector) Matches(s Segment) bool {
	if ss.Kind != s.Kind {
		return false
	}
	if ss.Name == "*" {
		return true
	}
	return ss.Name == s.Name
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
