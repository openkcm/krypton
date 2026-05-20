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

	// ErrInvalidPath is returned when the path has an incomplete type/name pair.
	ErrInvalidPath = errors.New("invalid path: must have even number of fields (type/name pairs)")

	// ErrInvalidField is returned when a field type or name contains invalid characters.
	ErrInvalidField = errors.New("field type and name must be non-empty and must not contain '*', '/', or whitespace")
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
	Domain Domain
	Fields []Field
}

// Field represents a type/name pair in the identity path.
type Field struct {
	Type string
	Name string
}

// Validate checks that type and name are non-empty and do not contain
// glob characters ('*'), slashes, or whitespace.
func (f Field) Validate() error {
	for _, v := range []string{f.Type, f.Name} {
		if v == "" || strings.ContainsAny(v, "*/\t\n\r ") {
			return ErrInvalidField
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

	for _, f := range id.Fields {
		b.WriteByte('/')
		b.WriteString(f.Type)
		b.WriteByte('/')
		b.WriteString(f.Name)
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
// or the path has an odd number of fields (incomplete type/name pair).
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

	fields := make([]Field, 0, len(parts)/2)
	for i := 0; i < len(parts); i += 2 {
		f := Field{Type: parts[i], Name: parts[i+1]}
		if err := f.Validate(); err != nil {
			return Identity{}, err
		}
		fields = append(fields, f)
	}

	return Identity{
		Domain: Domain(d),
		Fields: fields,
	}, nil
}
