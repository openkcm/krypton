package identity

import (
	"errors"
	"strings"
)

const (
	// Scheme is the URI scheme for krypton identities.
	Scheme = "kryptonid"

	// invalidChars contains characters that are not allowed in domain names,
	// field types, or field names.
	invalidChars = "*/\t\n\r "
)

var (
	// ErrInvalidScheme is returned when parsing a URI with wrong scheme.
	ErrInvalidScheme = errors.New("invalid scheme")

	// ErrEmptyDomain is returned when a domain is empty.
	ErrEmptyDomain = errors.New("domain cannot be empty")

	// ErrInvalidCharacters is returned when a domain, field type, or field name
	// contains characters from invalidChars.
	ErrInvalidCharacters = errors.New("contains invalid characters")

	// ErrInvalidPath is returned when the path has an incomplete type/name pair.
	ErrInvalidPath = errors.New("invalid path: must have even number of fields (type/name pairs)")

	// ErrEmptyField is returned when a field type or name is empty.
	ErrEmptyField = errors.New("field type and name must be non-empty")
)

type (
	// URI is the string representation of a krypton identity.
	URI string

	// Domain identifies a trust boundary for identities.
	Domain string

	// Field represents a type/name pair in the identity path.
	Field struct {
		Type string
		Name string
	}

	// Identity is a kryptonid:// URI representing any entity in Krypton.
	Identity struct {
		Domain Domain
		Fields []Field
	}
)

// Validate validates that the domain is non-empty and does not contain invalid characters.
func (d Domain) Validate() error {
	if d == "" {
		return ErrEmptyDomain
	}
	if strings.ContainsAny(string(d), invalidChars) {
		return ErrInvalidCharacters
	}
	return nil
}

// Validate validates that type and name are non-empty and do not contain invalid characters.
func (f Field) Validate() error {
	for _, v := range []string{f.Type, f.Name} {
		if v == "" {
			return ErrEmptyField
		}
		if strings.ContainsAny(v, invalidChars) {
			return ErrInvalidCharacters
		}
	}
	return nil
}

// URI returns the kryptonid:// string representation.
func (id *Identity) URI() URI {
	var b strings.Builder

	b.WriteString(Scheme)
	b.WriteString("://")
	b.WriteString(string(id.Domain))

	for _, f := range id.Fields {
		b.WriteByte('/')
		b.WriteString(f.Type)
		b.WriteByte('/')
		b.WriteString(f.Name)
	}

	return URI(b.String())
}

// Parse parses a kryptonid:// URI into an Identity.
// Returns an error if the scheme is wrong, domain is empty or invalid,
// or the path has an odd number of fields (incomplete type/name pair).
//
// Example URI: kryptonid://acme-corp/node/root
func Parse(uri URI) (Identity, error) {
	after, found := strings.CutPrefix(string(uri), Scheme+"://")
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
