package authz

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/openkcm/krypton/internal/authn"
)

var (
	// ErrInvalidPatternScheme is returned when parsing a pattern with wrong scheme.
	ErrInvalidPatternScheme = errors.New("invalid pattern scheme: must be 'kryptonid'")

	// ErrEmptyPatternTrustDomain is returned when pattern trust domain is empty.
	ErrEmptyPatternTrustDomain = errors.New("pattern trust domain cannot be empty")

	// ErrInvalidPatternPath is returned when the pattern path is malformed.
	ErrInvalidPatternPath = errors.New("invalid pattern path: must have kind/name pairs, optionally ending with **")
)

// IdentityPattern is a structured pattern for matching against authn.Identity values.
// TrustDomain is always literal (no wildcards).
type IdentityPattern struct {
	TrustDomain string
	Segments    []PatternSegment
}

// Matches checks if a concrete authn.Identity matches this pattern.
// Trust domain is always matched literally.
// "*" in a segment's Name matches any name for that kind.
// "**" as a trailing kind matches zero or more remaining segments of any kind.
// Pattern and value must have the same segment count unless pattern ends with "**".
func (p IdentityPattern) Matches(id authn.Identity) bool {
	if p.TrustDomain != id.TrustDomain {
		return false
	}

	for i, ps := range p.Segments {
		if ps.Kind == "**" {
			return true
		}
		if i >= len(id.Segments) {
			return false
		}
		if !ps.Matches(id.Segments[i]) {
			return false
		}
	}

	return len(p.Segments) == len(id.Segments)
}

// String returns the kryptonid:// URI representation of the pattern.
func (p IdentityPattern) String() string {
	var b strings.Builder

	b.WriteString(authn.Scheme)
	b.WriteString("://")
	b.WriteString(p.TrustDomain)

	for _, s := range p.Segments {
		b.WriteByte('/')
		if s.Kind == "**" {
			b.WriteString("**")
			break
		}
		b.WriteString(s.Kind)
		b.WriteByte('/')
		b.WriteString(s.Name)
	}

	return b.String()
}

// MarshalJSON serializes IdentityPattern as a URI string.
func (p IdentityPattern) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

// UnmarshalJSON deserializes IdentityPattern from a URI string.
func (p *IdentityPattern) UnmarshalJSON(data []byte) error {
	var uri string
	if err := json.Unmarshal(data, &uri); err != nil {
		return err
	}

	parsed, err := ParseIdentityPattern(uri)
	if err != nil {
		return err
	}

	*p = parsed
	return nil
}

// ParseIdentityPattern parses a kryptonid:// pattern string into an IdentityPattern.
// Returns an error if the scheme is wrong, trust domain is empty,
// or the path has an odd number of segments without a trailing "**".
func ParseIdentityPattern(s string) (IdentityPattern, error) {
	after, found := strings.CutPrefix(s, authn.Scheme+"://")
	if !found {
		return IdentityPattern{}, ErrInvalidPatternScheme
	}

	td, path, _ := strings.Cut(after, "/")
	if td == "" {
		return IdentityPattern{}, ErrEmptyPatternTrustDomain
	}

	if path == "" {
		return IdentityPattern{}, ErrInvalidPatternPath
	}

	parts := strings.Split(path, "/")
	var segments []PatternSegment

	for len(parts) > 0 {
		if parts[0] == "**" {
			segments = append(segments, PatternSegment{Kind: "**"})
			break
		}

		if len(parts) < 2 {
			return IdentityPattern{}, ErrInvalidPatternPath
		}

		segments = append(segments, PatternSegment{Kind: parts[0], Name: parts[1]})
		parts = parts[2:]
	}

	return IdentityPattern{TrustDomain: td, Segments: segments}, nil
}

// PatternSegment represents a kind/name pair in an identity pattern.
// Name can be "*" to match any name.
// Kind can be "**" to match zero or more trailing segments of any kind.
type PatternSegment struct {
	Kind string
	Name string
}

// Matches checks if this pattern segment matches a concrete segment.
// Kind must match exactly. Name must match exactly or pattern name is "*".
func (ps PatternSegment) Matches(s authn.Segment) bool {
	if ps.Kind != s.Kind {
		return false
	}
	if ps.Name == "*" {
		return true
	}
	return ps.Name == s.Name
}

// ActionPattern represents a matching template for actions.
// Only "*" (match all) or exact string equality.
type ActionPattern string

// Matches checks if an action matches this pattern.
func (p ActionPattern) Matches(action Action) bool {
	return string(p) == "*" || string(p) == string(action)
}

// matchesAnyIdentity checks if the identity matches any of the identity patterns.
func matchesAnyIdentity(patterns []IdentityPattern, id authn.Identity) bool {
	for _, p := range patterns {
		if p.Matches(id) {
			return true
		}
	}
	return false
}

// matchesAnyAction checks if the action matches any of the action patterns.
func matchesAnyAction(patterns []ActionPattern, action Action) bool {
	for _, p := range patterns {
		if p.Matches(action) {
			return true
		}
	}
	return false
}
