package identity

import (
	"encoding/json"
	"errors"
	"strings"
)

// Scheme is the URI scheme for krypton identities.
const Scheme = "kryptonid"

var (
	// ErrInvalidScheme is returned when parsing a URI with wrong scheme.
	ErrInvalidScheme = errors.New("invalid scheme: must be 'kryptonid'")

	// ErrEmptyDomain is returned when a domain is empty.
	ErrEmptyDomain = errors.New("domain cannot be empty")

	// ErrInvalidDomain is returned when a domain contains invalid characters.
	ErrInvalidDomain = errors.New("domain must not contain '*', '/', or whitespace")

	// ErrInvalidPath is returned when the path has an incomplete kind/name pair.
	ErrInvalidPath = errors.New("invalid path: must have even number of segments (kind/name pairs)")

	// ErrInvalidSegment is returned when a segment kind or name contains invalid characters.
	ErrInvalidSegment = errors.New("segment kind and name must be non-empty and must not contain '*', '/', or whitespace")
)

// Domain identifies a trust boundary for identities.
type Domain string

// String returns the domain as a string.
func (d Domain) String() string { return string(d) }

// Validate checks that the domain is non-empty and does not contain
// invalid characters (slashes, wildcards, whitespace).
func (d Domain) Validate() error {
	if d == "" {
		return ErrEmptyDomain
	}
	if strings.ContainsAny(string(d), "*/\t\n\r ") {
		return ErrInvalidDomain
	}
	return nil
}

// Identity is a kryptonid:// URI representing any entity in Krypton.
type Identity struct {
	Domain   Domain
	Segments []Segment
}

// Segment represents a kind/name pair in the identity path.
type Segment struct {
	Kind string
	Name string
}

// Validate checks that kind and name are non-empty and do not contain
// glob characters ('*'), slashes, or whitespace.
func (s Segment) Validate() error {
	for _, v := range []string{s.Kind, s.Name} {
		if v == "" || strings.ContainsAny(v, "*/\t\n\r ") {
			return ErrInvalidSegment
		}
	}
	return nil
}

// URI returns the kryptonid:// string representation.
func (id *Identity) URI() string {
	var b strings.Builder

	b.WriteString(Scheme)
	b.WriteString("://")
	b.WriteString(id.Domain.String())

	for _, s := range id.Segments {
		b.WriteByte('/')
		b.WriteString(s.Kind)
		b.WriteByte('/')
		b.WriteString(s.Name)
	}

	return b.String()
}

// MarshalJSON serializes Identity as a URI string.
func (id *Identity) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.URI())
}

// UnmarshalJSON deserializes Identity from a URI string.
func (id *Identity) UnmarshalJSON(data []byte) error {
	var uri string
	if err := json.Unmarshal(data, &uri); err != nil {
		return err
	}

	parsed, err := Parse(uri)
	if err != nil {
		return err
	}

	*id = parsed
	return nil
}

// Parse parses a kryptonid:// URI string into an Identity.
// Returns an error if the scheme is wrong, domain is empty or invalid,
// or the path has an odd number of segments (incomplete kind/name pair).
func Parse(uri string) (Identity, error) {
	after, found := strings.CutPrefix(uri, Scheme+"://")
	if !found {
		return Identity{}, ErrInvalidScheme
	}

	d, path, _ := strings.Cut(after, "/")
	if err := Domain(d).Validate(); err != nil {
		return Identity{}, err
	}

	if path == "" {
		return Identity{
			Domain: Domain(d),
		}, nil
	}

	parts := strings.Split(path, "/")
	if len(parts)%2 != 0 {
		return Identity{}, ErrInvalidPath
	}

	segments := make([]Segment, 0, len(parts)/2)
	for i := 0; i < len(parts); i += 2 {
		seg := Segment{Kind: parts[i], Name: parts[i+1]}
		if err := seg.Validate(); err != nil {
			return Identity{}, err
		}
		segments = append(segments, seg)
	}

	return Identity{
		Domain:   Domain(d),
		Segments: segments,
	}, nil
}
