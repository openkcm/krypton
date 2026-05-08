package authn

import (
	"encoding/json"
	"errors"
	"strings"
)

// Scheme is the URI scheme for krypton identities.
const Scheme = "kryptonid"

// KindNode is the segment kind for agent nodes in a topology.
const KindNode = "node"

var (
	// ErrInvalidScheme is returned when parsing a URI with wrong scheme.
	ErrInvalidScheme = errors.New("invalid scheme: must be 'kryptonid'")

	// ErrEmptyTrustDomain is returned when trust domain is empty.
	ErrEmptyTrustDomain = errors.New("trust domain cannot be empty")

	// ErrInvalidPath is returned when the path has an incomplete kind/name pair.
	ErrInvalidPath = errors.New("invalid path: must have even number of segments (kind/name pairs)")

	// ErrInvalidSegment is returned when a segment kind or name contains invalid characters.
	ErrInvalidSegment = errors.New("segment kind and name must be non-empty and must not contain '*', '/', or whitespace")
)

// Identity is a kryptonid:// URI representing any entity in Krypton.
type Identity struct {
	TrustDomain string
	Segments    []Segment
}

// Segment represents a kind/name pair in the identity path.
type Segment struct {
	Kind string
	Name string
}

// URI returns the kryptonid:// string representation.
func (id Identity) URI() string {
	var b strings.Builder

	b.WriteString(Scheme)
	b.WriteString("://")
	b.WriteString(id.TrustDomain)

	for _, s := range id.Segments {
		b.WriteByte('/')
		b.WriteString(s.Kind)
		b.WriteByte('/')
		b.WriteString(s.Name)
	}

	return b.String()
}

// MarshalJSON serializes Identity as a URI string.
func (id Identity) MarshalJSON() ([]byte, error) {
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
// Returns an error if the scheme is wrong, trust domain is empty,
// or the path has an odd number of segments (incomplete kind/name pair).
func Parse(uri string) (Identity, error) {
	after, found := strings.CutPrefix(uri, Scheme+"://")
	if !found {
		return Identity{}, ErrInvalidScheme
	}

	td, path, _ := strings.Cut(after, "/")
	if td == "" {
		return Identity{}, ErrEmptyTrustDomain
	}

	if path == "" {
		return Identity{TrustDomain: td}, nil
	}

	parts := strings.Split(path, "/")
	if len(parts)%2 != 0 {
		return Identity{}, ErrInvalidPath
	}

	segments := make([]Segment, 0, len(parts)/2)
	for i := 0; i < len(parts); i += 2 {
		if err := validateSegment(parts[i], parts[i+1]); err != nil {
			return Identity{}, err
		}
		segments = append(segments, Segment{Kind: parts[i], Name: parts[i+1]})
	}

	return Identity{TrustDomain: td, Segments: segments}, nil
}

// NodeIdentity creates a node identity for the given trust domain and name.
func NodeIdentity(trustDomain, name string) (Identity, error) {
	if err := validateSegment(KindNode, name); err != nil {
		return Identity{}, err
	}
	return Identity{
		TrustDomain: trustDomain,
		Segments: []Segment{
			{Kind: KindNode, Name: name},
		},
	}, nil
}

// validateSegment checks that kind and name are non-empty and do not contain
// glob characters ('*'), slashes, or whitespace.
func validateSegment(kind, name string) error {
	for _, s := range []string{kind, name} {
		if s == "" || strings.ContainsAny(s, "*/\t\n\r ") {
			return ErrInvalidSegment
		}
	}
	return nil
}
