package identity_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/identity"
)

func TestSelectorMatches(t *testing.T) {
	tests := []struct {
		name     string
		selector identity.Selector
		identity identity.Identity
		expMatch bool
	}{
		{
			name: "exact match single field",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: "root"}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "node", Name: "root"}},
			},
			expMatch: true,
		},
		{
			name: "exact match multiple fields",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			expMatch: true,
		},
		{
			name: "domain mismatch",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: "root"}},
			},
			identity: identity.Identity{
				Domain: "other",
				Fields: []identity.Field{{Type: "node", Name: "root"}},
			},
			expMatch: false,
		},
		{
			name: "name mismatch",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: "root"}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "node", Name: "agent-01"}},
			},
			expMatch: false,
		},
		{
			name: "type mismatch",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: "root"}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "user", Name: "root"}},
			},
			expMatch: false,
		},
		{
			name: "selector longer than identity",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "node", Name: "root"}},
			},
			expMatch: false,
		},
		{
			name: "identity longer than selector",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: "root"}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			expMatch: false,
		},
		{
			name: "single wildcard matches any name",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: identity.AnyName}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "node", Name: "agent-01"}},
			},
			expMatch: true,
		},
		{
			name: "any name requires type match",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: identity.AnyName}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "user", Name: "alice"}},
			},
			expMatch: false,
		},
		{
			name: "any remaining matches everything from position",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: identity.AnyRemaining}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			expMatch: true,
		},
		{
			name: "any remaining after prefix matches everything from position",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: identity.AnyRemaining},
				},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			expMatch: true,
		},
		{
			name: "any remaining after prefix with no remaining fields matches everything",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: identity.AnyRemaining},
				},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "node", Name: "root"}},
			},
			expMatch: true,
		},
		{
			name: "type-prefix any remaining matches any identity starting with type",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "user", Name: identity.AnyRemaining}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "user", Name: "alice"}},
			},
			expMatch: true,
		},
		{
			name: "type-prefix any remaining matches deeper identity",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "user", Name: identity.AnyRemaining}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{
					{Type: "user", Name: "alice"},
					{Type: "service", Name: "kms"},
				},
			},
			expMatch: true,
		},
		{
			name: "type-prefix any remaining rejects wrong type",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "user", Name: identity.AnyRemaining}},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "node", Name: "agent-01"}},
			},
			expMatch: false,
		},
		{
			name: "type-prefix any remaining after exact prefix",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: "service", Name: identity.AnyRemaining},
				},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			expMatch: true,
		},
		{
			name: "type-prefix any remaining rejects when identity too short",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: "service", Name: identity.AnyRemaining},
				},
			},
			identity: identity.Identity{
				Domain: "acme",
				Fields: []identity.Field{{Type: "node", Name: "root"}},
			},
			expMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got := tt.selector.Matches(tt.identity)

			// then
			assert.Equal(t, tt.expMatch, got)
		})
	}
}

func TestFieldSelectorMatches(t *testing.T) {
	tests := []struct {
		name     string
		fsel     identity.FieldSelector
		field    identity.Field
		expMatch bool
	}{
		{
			name:     "exact match",
			fsel:     identity.FieldSelector{Type: "node", Name: "root"},
			field:    identity.Field{Type: "node", Name: "root"},
			expMatch: true,
		},
		{
			name:     "type mismatch",
			fsel:     identity.FieldSelector{Type: "node", Name: "root"},
			field:    identity.Field{Type: "user", Name: "root"},
			expMatch: false,
		},
		{
			name:     "name mismatch",
			fsel:     identity.FieldSelector{Type: "node", Name: "root"},
			field:    identity.Field{Type: "node", Name: "agent-01"},
			expMatch: false,
		},
		{
			name:     "wildcard name matches any",
			fsel:     identity.FieldSelector{Type: "node", Name: identity.AnyName},
			field:    identity.Field{Type: "node", Name: "anything"},
			expMatch: true,
		},
		{
			name:     "wildcard name requires type match",
			fsel:     identity.FieldSelector{Type: "node", Name: identity.AnyName},
			field:    identity.Field{Type: "user", Name: "anything"},
			expMatch: false,
		},
		{
			name:     "type any remaining matches any field",
			fsel:     identity.FieldSelector{Type: identity.AnyRemaining},
			field:    identity.Field{Type: "node", Name: "root"},
			expMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got := tt.fsel.Matches(tt.field)

			// then
			assert.Equal(t, tt.expMatch, got)
		})
	}
}

func TestFieldSelectorValidate(t *testing.T) {
	tests := []struct {
		name   string
		fsel   identity.FieldSelector
		expErr error
	}{
		{
			name: "valid exact",
			fsel: identity.FieldSelector{Type: "node", Name: "root"},
		},
		{
			name: "valid wildcard name",
			fsel: identity.FieldSelector{Type: "node", Name: identity.AnyName},
		},
		{
			name: "valid type-prefix any remaining",
			fsel: identity.FieldSelector{Type: "node", Name: identity.AnyRemaining},
		},
		{
			name: "valid any remaining",
			fsel: identity.FieldSelector{Type: identity.AnyRemaining},
		},
		{
			name:   "empty type",
			fsel:   identity.FieldSelector{Type: "", Name: "root"},
			expErr: identity.ErrEmptyField,
		},
		{
			name:   "empty name",
			fsel:   identity.FieldSelector{Type: "node", Name: ""},
			expErr: identity.ErrEmptyField,
		},
		{
			name:   "invalid characters in type",
			fsel:   identity.FieldSelector{Type: "no de", Name: "root"},
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "invalid characters in name",
			fsel:   identity.FieldSelector{Type: "node", Name: "ro\tot"},
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "slash in type",
			fsel:   identity.FieldSelector{Type: "no/de", Name: "root"},
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "wildcard in type",
			fsel:   identity.FieldSelector{Type: "no*de", Name: "root"},
			expErr: identity.ErrInvalidCharacters,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.fsel.Validate()

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestParseSelector(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		expSelector identity.Selector
		expErr      error
	}{
		{
			name: "exact single field",
			raw:  "kryptonid://acme/node/root",
			expSelector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: "root"}},
			},
		},
		{
			name: "exact multiple fields",
			raw:  "kryptonid://acme/node/root/service/kms",
			expSelector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
		},
		{
			name: "single wildcard in name",
			raw:  "kryptonid://acme/node/*",
			expSelector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: identity.AnyName}},
			},
		},
		{
			name: "any remaining at start",
			raw:  "kryptonid://acme/**",
			expSelector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: identity.AnyRemaining}},
			},
		},
		{
			name: "any remaining after prefix",
			raw:  "kryptonid://acme/node/root/**",
			expSelector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: identity.AnyRemaining},
				},
			},
		},
		{
			name: "type-prefix any remaining",
			raw:  "kryptonid://acme/user/**",
			expSelector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "user", Name: identity.AnyRemaining}},
			},
		},
		{
			name: "type-prefix any remaining after exact field",
			raw:  "kryptonid://acme/node/root/service/**",
			expSelector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: "service", Name: identity.AnyRemaining},
				},
			},
		},
		{
			name:   "wrong scheme",
			raw:    "https://acme/node/root",
			expErr: identity.ErrInvalidScheme,
		},
		{
			name:   "no scheme",
			raw:    "acme/node/root",
			expErr: identity.ErrInvalidScheme,
		},
		{
			name:   "empty domain",
			raw:    "kryptonid:///node/root",
			expErr: identity.ErrEmptyDomain,
		},
		{
			name:   "empty path",
			raw:    "kryptonid://acme",
			expErr: identity.ErrInvalidSelectorPath,
		},
		{
			name:   "odd path segments",
			raw:    "kryptonid://acme/node",
			expErr: identity.ErrInvalidSelectorPath,
		},
		{
			name:   "trailing type without name",
			raw:    "kryptonid://acme/node/root/service",
			expErr: identity.ErrInvalidSelectorPath,
		},
		{
			name:   "empty type segment",
			raw:    "kryptonid://acme//root",
			expErr: identity.ErrEmptyField,
		},
		{
			name:   "empty name segment",
			raw:    "kryptonid://acme/node/",
			expErr: identity.ErrEmptyField,
		},
		{
			name:   "invalid characters in type",
			raw:    "kryptonid://acme/no de/root",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "invalid characters in name",
			raw:    "kryptonid://acme/node/ro\tot",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "wildcard in type",
			raw:    "kryptonid://acme/no*de/root",
			expErr: identity.ErrInvalidCharacters,
		},
		{
			name:   "non-terminal any remaining in type position",
			raw:    "kryptonid://acme/**/service/kms",
			expErr: identity.ErrInvalidSelectorPath,
		},
		{
			name:   "non-terminal any remaining in name position",
			raw:    "kryptonid://acme/node/**/service/kms",
			expErr: identity.ErrInvalidSelectorPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got, err := identity.ParseSelector(tt.raw)

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expSelector, got)
		})
	}
}

func TestSelectorString(t *testing.T) {
	tests := []struct {
		name     string
		selector identity.Selector
		expStr   string
	}{
		{
			name: "exact single field",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: "root"}},
			},
			expStr: "kryptonid://acme/node/root",
		},
		{
			name: "exact multiple fields",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: "service", Name: "kms"},
				},
			},
			expStr: "kryptonid://acme/node/root/service/kms",
		},
		{
			name: "any remaining at start",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: identity.AnyRemaining}},
			},
			expStr: "kryptonid://acme/**",
		},
		{
			name: "any remaining after prefix",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: identity.AnyRemaining},
				},
			},
			expStr: "kryptonid://acme/node/root/**",
		},
		{
			name: "type-prefix any remaining",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "user", Name: identity.AnyRemaining}},
			},
			expStr: "kryptonid://acme/user/**",
		},
		{
			name: "type-prefix any remaining after exact field",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{
					{Type: "node", Name: "root"},
					{Type: "service", Name: identity.AnyRemaining},
				},
			},
			expStr: "kryptonid://acme/node/root/service/**",
		},
		{
			name: "single wildcard in name",
			selector: identity.Selector{
				Domain: "acme",
				Fields: []identity.FieldSelector{{Type: "node", Name: identity.AnyName}},
			},
			expStr: "kryptonid://acme/node/*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got := tt.selector.String()

			// then
			assert.Equal(t, tt.expStr, got)
		})
	}
}

func TestParseSelectorRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "exact", raw: "kryptonid://acme/node/root/service/kms"},
		{name: "wildcard name", raw: "kryptonid://acme/node/*/service/kms"},
		{name: "any remaining", raw: "kryptonid://acme/**"},
		{name: "any remaining after prefix", raw: "kryptonid://acme/node/root/**"},
		{name: "type-prefix any remaining", raw: "kryptonid://acme/user/**"},
		{name: "type-prefix any remaining after prefix", raw: "kryptonid://acme/node/root/service/**"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			parsed, err := identity.ParseSelector(tt.raw)

			// then
			assert.NoError(t, err)
			assert.Equal(t, tt.raw, parsed.String())
		})
	}
}
