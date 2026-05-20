package identity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/identity"
)

func TestDomainValidate(t *testing.T) {
	tests := []struct {
		name   string
		domain identity.Domain
		expErr error
	}{
		{
			name:   "valid simple domain",
			domain: "acme-corp",
		},
		{
			name:   "valid domain with dots",
			domain: "my.org.example",
		},
		{
			name:   "empty domain",
			domain: "",
			expErr: identity.ErrEmptyDomain,
		},
		{
			name:   "domain with wildcard",
			domain: "acme*",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "domain with slash",
			domain: "acme/corp",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "domain with space",
			domain: "acme corp",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "domain with tab",
			domain: "acme\tcorp",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "domain with newline",
			domain: "acme\ncorp",
			expErr: identity.ErrInvalidCharacters,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.domain.Validate()

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestFieldValidate(t *testing.T) {
	tests := []struct {
		name   string
		field  identity.Field
		expErr error
	}{
		{
			name:  "valid field",
			field: identity.Field{Type: "node", Name: "root"},
		},
		{
			name:   "empty type",
			field:  identity.Field{Type: "", Name: "root"},
			expErr: identity.ErrEmptyField,
		},
		{
			name:   "empty name",
			field:  identity.Field{Type: "node", Name: ""},
			expErr: identity.ErrEmptyField,
		},
		{
			name:   "type with wildcard",
			field:  identity.Field{Type: "no*de", Name: "root"},
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "name with slash",
			field:  identity.Field{Type: "node", Name: "ro/ot"},
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "type with space",
			field:  identity.Field{Type: "no de", Name: "root"},
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "name with tab",
			field:  identity.Field{Type: "node", Name: "ro\tot"},
			expErr: identity.ErrInvalidCharacters,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.field.Validate()

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestIdentityURI(t *testing.T) {
	tests := []struct {
		name     string
		identity identity.Identity
		expURI   identity.URI
	}{
		{
			name:     "domain only",
			identity: identity.Identity{Domain: "acme-corp"},
			expURI:   "kryptonid://acme-corp",
		},
		{
			name: "single field",
			identity: identity.Identity{
				Domain: "acme-corp",
				Fields: []identity.Field{{Type: "node", Name: "root"}},
			},
			expURI: "kryptonid://acme-corp/node/root",
		},
		{
			name: "multiple fields",
			identity: identity.Identity{
				Domain: "acme-corp",
				Fields: []identity.Field{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			expURI: "kryptonid://acme-corp/node/root/service/kms",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got := tt.identity.URI()

			// then
			assert.Equal(t, tt.expURI, got)
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		uri         identity.URI
		expIdentity identity.Identity
		expErr      error
	}{
		{
			name:        "domain only",
			uri:         "kryptonid://acme-corp",
			expIdentity: identity.Identity{Domain: "acme-corp"},
		},
		{
			name: "single field",
			uri:  "kryptonid://acme-corp/node/root",
			expIdentity: identity.Identity{
				Domain: "acme-corp",
				Fields: []identity.Field{{Type: "node", Name: "root"}},
			},
		},
		{
			name: "multiple fields",
			uri:  "kryptonid://acme-corp/node/root/service/kms",
			expIdentity: identity.Identity{
				Domain: "acme-corp",
				Fields: []identity.Field{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
		},
		{
			name:   "wrong scheme",
			uri:    "https://acme-corp/node/root",
			expErr: identity.ErrInvalidScheme,
		},
		{
			name:   "no scheme",
			uri:    "acme-corp/node/root",
			expErr: identity.ErrInvalidScheme,
		},
		{
			name:   "empty domain",
			uri:    "kryptonid:///node/root",
			expErr: identity.ErrEmptyDomain,
		},
		{
			name:   "invalid domain with wildcard",
			uri:    "kryptonid://acme*corp/node/root",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "odd number of path segments",
			uri:    "kryptonid://acme-corp/node",
			expErr: identity.ErrInvalidPath,
		},
		{
			name:   "three path segments",
			uri:    "kryptonid://acme-corp/node/root/service",
			expErr: identity.ErrInvalidPath,
		},
		{
			name:   "field with wildcard in type",
			uri:    "kryptonid://acme-corp/no*de/root",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "field with empty name segment",
			uri:    "kryptonid://acme-corp/node/",
			expErr: identity.ErrEmptyField,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got, err := identity.Parse(tt.uri)

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expIdentity, got)
		})
	}
}

func TestParseRoundTrip(t *testing.T) {
	// given
	original := identity.Identity{
		Domain: "acme-corp",
		Fields: []identity.Field{
			{Type: "node", Name: "root"},
			{Type: "region", Name: "eu-west-1"},
		},
	}

	// when
	uri := original.URI()
	parsed, err := identity.Parse(uri)

	// then
	assert.NoError(t, err)
	assert.Equal(t, original, parsed)
}
