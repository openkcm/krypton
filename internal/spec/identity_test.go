package spec_test

import (
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func TestKryptonID_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   spec.KryptonID
		exp  string
	}{
		{
			name: "root identity",
			id:   spec.RootID("acme-corp"),
			exp:  "kryptonid://acme-corp/root",
		},
		{
			name: "agent identity",
			id:   spec.AgentID("acme-corp", "agent-aws"),
			exp:  "kryptonid://acme-corp/agent/agent-aws",
		},
		{
			name: "agent with hyphenated trust domain",
			id:   spec.AgentID("prod.acme-corp", "agent-leaf"),
			exp:  "kryptonid://prod.acme-corp/agent/agent-leaf",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// when
			got := tt.id.URI()

			// then
			assert.Equal(t, tt.exp, got)
		})
	}
}

func TestKryptonID_PrincipalName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   spec.KryptonID
		exp  string
	}{
		{
			name: "root returns root",
			id:   spec.RootID("acme-corp"),
			exp:  "root",
		},
		{
			name: "agent returns agent name",
			id:   spec.AgentID("acme-corp", "agent-aws"),
			exp:  "agent-aws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// when
			got := tt.id.PrincipalName()

			// then
			assert.Equal(t, tt.exp, got)
		})
	}
}

func TestKryptonID_IsRoot(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   spec.KryptonID
		exp  bool
	}{
		{
			name: "root is root",
			id:   spec.RootID("acme-corp"),
			exp:  true,
		},
		{
			name: "agent is not root",
			id:   spec.AgentID("acme-corp", "agent-aws"),
			exp:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// when
			got := tt.id.IsRoot()

			// then
			assert.Equal(t, tt.exp, got)
		})
	}
}

func TestParseKryptonID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		uri    string
		exp    spec.KryptonID
		expErr error
	}{
		{
			name: "valid root",
			uri:  "kryptonid://acme-corp/root",
			exp:  spec.RootID("acme-corp"),
		},
		{
			name: "valid agent",
			uri:  "kryptonid://acme-corp/agent/agent-aws",
			exp:  spec.AgentID("acme-corp", "agent-aws"),
		},
		{
			name: "valid agent with dotted trust domain",
			uri:  "kryptonid://prod.acme-corp/agent/agent-leaf",
			exp:  spec.AgentID("prod.acme-corp", "agent-leaf"),
		},
		{
			name:   "invalid scheme",
			uri:    "spiffe://acme-corp/agent/agent-aws",
			expErr: spec.ErrInvalidScheme,
		},
		{
			name:   "empty trust domain",
			uri:    "kryptonid:///root",
			expErr: spec.ErrEmptyTrustDomain,
		},
		{
			name:   "invalid role",
			uri:    "kryptonid://acme-corp/service/my-service",
			expErr: spec.ErrInvalidIdentityRole,
		},
		{
			name:   "agent without name",
			uri:    "kryptonid://acme-corp/agent/",
			expErr: spec.ErrEmptyAgentName,
		},
		{
			name:   "agent with missing name path",
			uri:    "kryptonid://acme-corp/agent",
			expErr: spec.ErrEmptyAgentName,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// when
			got, err := spec.ParseKryptonID(tt.uri)

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.exp, got)
		})
	}
}

func TestParseKryptonID_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   spec.KryptonID
	}{
		{
			name: "root round trip",
			id:   spec.RootID("acme-corp"),
		},
		{
			name: "agent round trip",
			id:   spec.AgentID("acme-corp", "agent-aws"),
		},
		{
			name: "agent with dotted trust domain",
			id:   spec.AgentID("prod.acme-corp", "agent-leaf"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			uri := tt.id.URI()

			// when
			got, err := spec.ParseKryptonID(uri)

			// then
			assert.NoError(t, err)
			assert.Equal(t, tt.id, got)
		})
	}
}

func TestKryptonIDFromCertificate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		uris   []string
		exp    spec.KryptonID
		expErr error
	}{
		{
			name: "valid krypton ID in URI SAN",
			uris: []string{"kryptonid://acme-corp/agent/agent-aws"},
			exp:  spec.AgentID("acme-corp", "agent-aws"),
		},
		{
			name: "krypton ID among other URIs",
			uris: []string{
				"https://example.com",
				"kryptonid://acme-corp/root",
				"spiffe://other/workload",
			},
			exp: spec.RootID("acme-corp"),
		},
		{
			name:   "no krypton ID",
			uris:   []string{"https://example.com", "spiffe://other/workload"},
			expErr: spec.ErrNoKryptonID,
		},
		{
			name:   "empty URIs",
			uris:   []string{},
			expErr: spec.ErrNoKryptonID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			cert := &x509.Certificate{}
			for _, u := range tt.uris {
				parsed, err := url.Parse(u)
				assert.NoError(t, err)
				cert.URIs = append(cert.URIs, parsed)
			}

			// when
			got, err := spec.KryptonIDFromCertificate(cert)

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.exp, got)
		})
	}
}

func TestRootID(t *testing.T) {
	t.Parallel()

	// when
	id := spec.RootID("acme-corp")

	// then
	assert.Equal(t, "acme-corp", id.TrustDomain)
	assert.Equal(t, spec.RootRole, id.Role)
	assert.Empty(t, id.Name)
	assert.True(t, id.IsRoot())
}

func TestAgentID(t *testing.T) {
	t.Parallel()

	// when
	id := spec.AgentID("acme-corp", "agent-aws")

	// then
	assert.Equal(t, "acme-corp", id.TrustDomain)
	assert.Equal(t, spec.DefaultRole, id.Role)
	assert.Equal(t, "agent-aws", id.Name)
	assert.False(t, id.IsRoot())
}
