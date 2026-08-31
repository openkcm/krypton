package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/identity"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/tlsconf"
)

func TestMTLSConfig_Validate(t *testing.T) {
	// given
	tests := []struct {
		name    string
		config  *config.MTLSConfig
		wantErr error
	}{
		{
			name: "valid config with non-empty paths",
			config: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "server-cert.pem",
					KeyPath:  "server-key.pem",
					CAPath:   "ca-cert.pem",
				},
				Client: tlsconf.Client{
					CertPath: "client-cert.pem",
					KeyPath:  "client-key.pem",
					CAPath:   "ca-cert.pem",
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid config with empty server cert path",
			config: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "",
					KeyPath:  "server-key.pem",
					CAPath:   "ca-cert.pem",
				},
				Client: tlsconf.Client{
					CertPath: "client-cert.pem",
					KeyPath:  "client-key.pem",
					CAPath:   "ca-cert.pem",
				},
			},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name: "invalid config with empty server key path",
			config: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "server-cert.pem",
					KeyPath:  "",
					CAPath:   "ca-cert.pem",
				},
				Client: tlsconf.Client{
					CertPath: "client-cert.pem",
					KeyPath:  "client-key.pem",
					CAPath:   "ca-cert.pem",
				},
			},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name: "invalid config with empty server CA path",
			config: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "server-cert.pem",
					KeyPath:  "server-key.pem",
					CAPath:   "",
				},
				Client: tlsconf.Client{
					CertPath: "client-cert.pem",
					KeyPath:  "client-key.pem",
					CAPath:   "ca-cert.pem",
				},
			},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name: "invalid config with empty client cert path",
			config: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "server-cert.pem",
					KeyPath:  "server-key.pem",
					CAPath:   "ca-cert.pem",
				},
				Client: tlsconf.Client{
					CertPath: "",
					KeyPath:  "client-key.pem",
					CAPath:   "ca-cert.pem",
				},
			},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name: "invalid config with empty client key path",
			config: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "server-cert.pem",
					KeyPath:  "server-key.pem",
					CAPath:   "ca-cert.pem",
				},
				Client: tlsconf.Client{
					CertPath: "client-cert.pem",
					KeyPath:  "",
					CAPath:   "ca-cert.pem",
				},
			},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name: "invalid config with empty client CA path",
			config: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "server-cert.pem",
					KeyPath:  "server-key.pem",
					CAPath:   "ca-cert.pem",
				},
				Client: tlsconf.Client{
					CertPath: "client-cert.pem",
					KeyPath:  "client-key.pem",
					CAPath:   "",
				},
			},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name:    "invalid config with zero-value struct",
			config:  &config.MTLSConfig{},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.config.Validate()

			// then
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestMTLSConfig_AuthType(t *testing.T) {
	// given
	cfg := &config.MTLSConfig{}

	// when
	authType := cfg.AuthType()

	// then
	assert.Equal(t, config.AuthTypeMTLS, authType)
}

func TestRootAuthConfig_UnmarshalYAML_Valid(t *testing.T) {
	// given
	yamlData := `
type: mtls
identities:
  - name: root-node
    uri: kryptonid://acme-corp/service/root
  - name: kms-service
    uri: kryptonid://acme-corp/service/agent
config:
  server:
    cert_path: /etc/certs/server.crt
    key_path: /etc/certs/server.key
    ca_path: /etc/certs/ca.crt
  client:
    cert_path: /etc/certs/client.crt
    key_path: /etc/certs/client.key
    ca_path: /etc/certs/ca.crt
`

	var cfg config.RootAuthConfig

	// when
	err := yaml.Unmarshal([]byte(yamlData), &cfg)

	// then
	assert.NoError(t, err)
	assert.Equal(t, config.AuthTypeMTLS, cfg.AuthType)
	require.Len(t, cfg.Identities, 2)
	assert.Equal(t, "root-node", cfg.Identities[0].Name)
	assert.Equal(t, identity.URI("kryptonid://acme-corp/service/root"), cfg.Identities[0].URI)

	assert.Equal(t, "kms-service", cfg.Identities[1].Name)
	assert.Equal(t, identity.URI("kryptonid://acme-corp/service/agent"), cfg.Identities[1].URI)

	mtlsConfig, ok := cfg.Config.(*config.MTLSConfig)
	assert.True(t, ok)
	assert.Equal(t, "/etc/certs/server.crt", mtlsConfig.Server.CertPath)
	assert.Equal(t, "/etc/certs/server.key", mtlsConfig.Server.KeyPath)
	assert.Equal(t, "/etc/certs/ca.crt", mtlsConfig.Server.CAPath)
	assert.Equal(t, "/etc/certs/client.crt", mtlsConfig.Client.CertPath)
	assert.Equal(t, "/etc/certs/client.key", mtlsConfig.Client.KeyPath)
	assert.Equal(t, "/etc/certs/ca.crt", mtlsConfig.Client.CAPath)
}

func TestRootAuthConfig_UnmarshalYAML_Error(t *testing.T) {
	// given
	// type is set to an unknown value, which should trigger an error during unmarshalling.
	yamlData := `
type: unknown
identities:
  - name: root-node
    uri: kryptonid://acme-corp/service/root
  - name: kms-service
    uri: kryptonid://acme-corp/service/agent
config:
  server:
    cert_path: /etc/certs/server.crt
    key_path: /etc/certs/server.key
    ca_path: /etc/certs/ca.crt
  client:
    cert_path: /etc/certs/client.crt
    key_path: /etc/certs/client.key
    ca_path: /etc/certs/ca.crt
`

	var cfg config.RootAuthConfig

	// when
	err := yaml.Unmarshal([]byte(yamlData), &cfg)

	// then
	assert.ErrorIs(t, err, config.ErrUnknownAuthType)
}

func TestRootAuthConfig_UnmarshalYAML_MissingAuthBlock(t *testing.T) {
	// given
	// type is set but the auth block is omitted, exercising the Kind==0 branch.
	yamlData := `
type: mtls
identities:
  - name: root-node
    uri: kryptonid://acme-corp/service/root
`

	var cfg config.RootAuthConfig

	// when
	err := yaml.Unmarshal([]byte(yamlData), &cfg)

	// then
	require.NoError(t, err)
	assert.Equal(t, config.AuthTypeMTLS, cfg.AuthType)
	require.NotNil(t, cfg.Config)

	mtlsConfig, ok := cfg.Config.(*config.MTLSConfig)
	require.True(t, ok)
	// Auth was not decoded, so all paths remain zero-value.
	assert.Empty(t, mtlsConfig.Server.CertPath)
	assert.Empty(t, mtlsConfig.Client.CertPath)
	// Validate should fail on the zero-value config.
	assert.ErrorIs(t, mtlsConfig.Validate(), tlsconf.ErrInvalidTLSConfig)
}

func TestAgentAuthConfig_UnmarshalYAML_Valid(t *testing.T) {
	// given
	yamlData := `
type: mtls
config:
  server:
    cert_path: /etc/certs/server.crt
    key_path: /etc/certs/server.key
    ca_path: /etc/certs/ca.crt
  client:
    cert_path: /etc/certs/client.crt
    key_path: /etc/certs/client.key
    ca_path: /etc/certs/ca.crt
`

	var cfg config.AgentAuthConfig

	// when
	err := yaml.Unmarshal([]byte(yamlData), &cfg)

	// then
	assert.NoError(t, err)
	assert.Equal(t, config.AuthTypeMTLS, cfg.AuthType)

	mtlsConfig, ok := cfg.Config.(*config.MTLSConfig)
	assert.True(t, ok)
	assert.Equal(t, "/etc/certs/server.crt", mtlsConfig.Server.CertPath)
	assert.Equal(t, "/etc/certs/server.key", mtlsConfig.Server.KeyPath)
	assert.Equal(t, "/etc/certs/ca.crt", mtlsConfig.Server.CAPath)
	assert.Equal(t, "/etc/certs/client.crt", mtlsConfig.Client.CertPath)
	assert.Equal(t, "/etc/certs/client.key", mtlsConfig.Client.KeyPath)
	assert.Equal(t, "/etc/certs/ca.crt", mtlsConfig.Client.CAPath)
}

func TestAgentAuthConfig_UnmarshalYAML_Error(t *testing.T) {
	// given
	// type is set to an unknown value, which should trigger an error during unmarshalling.
	yamlData := `
type: unknown
config:
  server:
    cert_path: /etc/certs/server.crt
    key_path: /etc/certs/server.key
    ca_path: /etc/certs/ca.crt
  client:
    cert_path: /etc/certs/client.crt
    key_path: /etc/certs/client.key
    ca_path: /etc/certs/ca.crt
`

	var cfg config.AgentAuthConfig

	// when
	err := yaml.Unmarshal([]byte(yamlData), &cfg)

	// then
	assert.ErrorIs(t, err, config.ErrUnknownAuthType)
}

func TestAgentAuthConfig_UnmarshalYAML_MissingAuthBlock(t *testing.T) {
	// given
	// type is set but the auth block is omitted, exercising the Kind==0 branch.
	yamlData := `
type: mtls
`

	var cfg config.AgentAuthConfig

	// when
	err := yaml.Unmarshal([]byte(yamlData), &cfg)

	// then
	require.NoError(t, err)
	assert.Equal(t, config.AuthTypeMTLS, cfg.AuthType)
	require.NotNil(t, cfg.Config)

	mtlsConfig, ok := cfg.Config.(*config.MTLSConfig)
	require.True(t, ok)
	// Auth was not decoded, so all paths remain zero-value.
	assert.Empty(t, mtlsConfig.Server.CertPath)
	assert.Empty(t, mtlsConfig.Client.CertPath)
	// Validate should fail on the zero-value config.
	assert.ErrorIs(t, mtlsConfig.Validate(), tlsconf.ErrInvalidTLSConfig)
}

func TestAuthConfig_UnmarshalYAML_EmptyAuthType(t *testing.T) {
	// given
	// type is empty, which should trigger ErrUnknownAuthType.
	yamlData := `
type: ""
`

	t.Run("RootAuthConfig", func(t *testing.T) {
		var cfg config.RootAuthConfig

		// when
		err := yaml.Unmarshal([]byte(yamlData), &cfg)

		// then
		assert.ErrorIs(t, err, config.ErrUnknownAuthType)
	})

	t.Run("AgentAuthConfig", func(t *testing.T) {
		var cfg config.AgentAuthConfig

		// when
		err := yaml.Unmarshal([]byte(yamlData), &cfg)

		// then
		assert.ErrorIs(t, err, config.ErrUnknownAuthType)
	})
}

func TestRootAuthConfig_Validate(t *testing.T) {
	// given
	tts := []struct {
		name    string
		cfg     config.RootAuthConfig
		wantErr error
	}{
		{
			name: "valid mtls config",
			cfg: config.RootAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Identities: []config.IdentityConfig{
					{
						Name: "root-node",
						URI:  "kryptonid://acme-corp/service/root",
					},
				},
				Config: &config.MTLSConfig{
					Server: tlsconf.Server{
						CertPath: "server-cert.pem",
						KeyPath:  "server-key.pem",
						CAPath:   "ca-cert.pem",
					},
					Client: tlsconf.Client{
						CertPath: "client-cert.pem",
						KeyPath:  "client-key.pem",
						CAPath:   "ca-cert.pem",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid mtls config with empty server cert path",
			cfg: config.RootAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Identities: []config.IdentityConfig{
					{
						Name: "root-node",
						URI:  "kryptonid://acme-corp/service/root",
					},
				},
				Config: &config.MTLSConfig{
					Server: tlsconf.Server{
						CertPath: "",
						KeyPath:  "server-key.pem",
						CAPath:   "ca-cert.pem",
					},
					Client: tlsconf.Client{
						CertPath: "client-cert.pem",
						KeyPath:  "client-key.pem",
						CAPath:   "ca-cert.pem",
					},
				},
			},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name: "unknown auth type",
			cfg: config.RootAuthConfig{
				AuthType: "unknown",
				Identities: []config.IdentityConfig{
					{
						Name: "root-node",
						URI:  "kryptonid://acme-corp/service/root",
					},
				},
				Config: nil,
			},
			wantErr: config.ErrUnknownAuthType,
		},
		{
			name: "nil config for mtls",
			cfg: config.RootAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Identities: []config.IdentityConfig{
					{
						Name: "root-node",
						URI:  "kryptonid://acme-corp/service/root",
					},
				},
				Config: nil,
			},
			wantErr: config.ErrNilConfig,
		},
		{
			name: "empty identities for mtls",
			cfg: config.RootAuthConfig{
				AuthType:   config.AuthTypeMTLS,
				Identities: []config.IdentityConfig{},
				Config: &config.MTLSConfig{
					Server: tlsconf.Server{
						CertPath: "server-cert.pem",
						KeyPath:  "server-key.pem",
						CAPath:   "ca-cert.pem",
					},
					Client: tlsconf.Client{
						CertPath: "client-cert.pem",
						KeyPath:  "client-key.pem",
						CAPath:   "ca-cert.pem",
					},
				},
			},
			wantErr: config.ErrInvalidIdentities,
		},
		{
			name: "invalid identity URI for mtls",
			cfg: config.RootAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Identities: []config.IdentityConfig{
					{
						Name: "root-node",
						URI:  "invalid-uri",
					},
				},
				Config: &config.MTLSConfig{
					Server: tlsconf.Server{
						CertPath: "server-cert.pem",
						KeyPath:  "server-key.pem",
						CAPath:   "ca-cert.pem",
					},
					Client: tlsconf.Client{
						CertPath: "client-cert.pem",
						KeyPath:  "client-key.pem",
						CAPath:   "ca-cert.pem",
					},
				},
			},
			wantErr: config.ErrInvalidIdentities,
		},
		{
			name: "empty identity name for mtls",
			cfg: config.RootAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Identities: []config.IdentityConfig{
					{
						Name: "",
						URI:  "kryptonid://acme-corp/service/root",
					},
				},
				Config: &config.MTLSConfig{
					Server: tlsconf.Server{
						CertPath: "server-cert.pem",
						KeyPath:  "server-key.pem",
						CAPath:   "ca-cert.pem",
					},
					Client: tlsconf.Client{
						CertPath: "client-cert.pem",
						KeyPath:  "client-key.pem",
						CAPath:   "ca-cert.pem",
					},
				},
			},
			wantErr: config.ErrInvalidIdentities,
		},
		{
			name: "spaced empty identity name for mtls",
			cfg: config.RootAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Identities: []config.IdentityConfig{
					{
						Name: "   ",
						URI:  "kryptonid://acme-corp/service/root",
					},
				},
				Config: &config.MTLSConfig{
					Server: tlsconf.Server{
						CertPath: "server-cert.pem",
						KeyPath:  "server-key.pem",
						CAPath:   "ca-cert.pem",
					},
					Client: tlsconf.Client{
						CertPath: "client-cert.pem",
						KeyPath:  "client-key.pem",
						CAPath:   "ca-cert.pem",
					},
				},
			},
			wantErr: config.ErrInvalidIdentities,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.cfg.Validate()

			// then
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestAgentAuthConfig_Validate(t *testing.T) {
	// given
	tts := []struct {
		name    string
		cfg     config.AgentAuthConfig
		wantErr error
	}{
		{
			name: "valid mtls config",
			cfg: config.AgentAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Config: &config.MTLSConfig{
					Server: tlsconf.Server{
						CertPath: "server-cert.pem",
						KeyPath:  "server-key.pem",
						CAPath:   "ca-cert.pem",
					},
					Client: tlsconf.Client{
						CertPath: "client-cert.pem",
						KeyPath:  "client-key.pem",
						CAPath:   "ca-cert.pem",
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid mtls config with empty client cert path",
			cfg: config.AgentAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Config: &config.MTLSConfig{
					Server: tlsconf.Server{
						CertPath: "server-cert.pem",
						KeyPath:  "server-key.pem",
						CAPath:   "ca-cert.pem",
					},
					Client: tlsconf.Client{
						CertPath: "",
						KeyPath:  "client-key.pem",
						CAPath:   "ca-cert.pem",
					},
				},
			},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name: "unknown auth type",
			cfg: config.AgentAuthConfig{
				AuthType: "unknown",
				Config:   nil,
			},
			wantErr: config.ErrUnknownAuthType,
		},
		{
			name: "nil config for mtls",
			cfg: config.AgentAuthConfig{
				AuthType: config.AuthTypeMTLS,
				Config:   nil,
			},
			wantErr: config.ErrNilConfig,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.cfg.Validate()

			// then
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

type fakeAuthConfig struct{}

func (f *fakeAuthConfig) AuthType() config.AuthType { return "fake" }
func (f *fakeAuthConfig) Validate() error           { return nil }

func TestGetAuthConfig(t *testing.T) {
	// given
	tts := []struct {
		name    string
		input   config.AuthConfig
		wantErr error
	}{
		{
			name: "valid MTLSConfig",
			input: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "server-cert.pem",
					KeyPath:  "server-key.pem",
					CAPath:   "ca-cert.pem",
				},
				Client: tlsconf.Client{
					CertPath: "client-cert.pem",
					KeyPath:  "client-key.pem",
					CAPath:   "ca-cert.pem",
				},
			},
			wantErr: nil,
		},
		{
			name:    "non-MTLS config returns error",
			input:   &fakeAuthConfig{},
			wantErr: config.ErrUnknownAuthType,
		},
		{
			name:    "nil interface returns error",
			input:   nil,
			wantErr: config.ErrUnknownAuthType,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result, err := config.GetAuthConfig(tt.input)

			// then
			assert.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr != nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestIdentities_URIs(t *testing.T) {
	// given
	cfg := config.RootAuthConfig{
		Identities: []config.IdentityConfig{
			{
				Name: "root-node",
				URI:  "kryptonid://acme-corp/service/root",
			},
			{
				Name: "kms-service",
				URI:  "kryptonid://acme-corp/service/agent",
			},
		},
	}

	expectedURIs := []string{
		"kryptonid://acme-corp/service/root",
		"kryptonid://acme-corp/service/agent",
	}

	// when
	actURIs := cfg.Identities.URIs()

	// then
	assert.Equal(t, expectedURIs, actURIs)
}

func TestIdentities_ValidateAuthIdentities(t *testing.T) {
	// given
	tts := []struct {
		name       string
		cfg        *config.RootConfig
		identities config.Identities
		wantErr    error
	}{
		{
			name: "valid identities",
			cfg: &config.RootConfig{
				Name: "root-node",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{Name: "segment1"},
					},
				},
			},
			identities: config.Identities{
				{Name: "root-node", URI: "kryptonid://acme-corp/service/root"},
				{Name: "segment1", URI: "kryptonid://acme-corp/service/segment1"},
			},
			wantErr: nil,
		},
		{
			name: "only root identity provided",
			cfg: &config.RootConfig{
				Name:     "root-node",
				Topology: spec.Topology{},
			},
			identities: config.Identities{
				{Name: "root-node", URI: "kryptonid://acme-corp/service/root"},
			},
			wantErr: nil,
		},
		{
			name: "missing identity for segment",
			cfg: &config.RootConfig{
				Name: "root-node",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{Name: "segment1"},
						{Name: "segment2"},
					},
				},
			},
			identities: config.Identities{
				{Name: "root-node", URI: "kryptonid://acme-corp/service/root"},
				{Name: "segment1", URI: "kryptonid://acme-corp/service/segment1"},
			},
			wantErr: config.ErrInvalidIdentities,
		},
		{
			name: "extra identity not in topology",
			cfg: &config.RootConfig{
				Name: "root-node",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{Name: "segment1"},
					},
				},
			},
			identities: config.Identities{
				{Name: "root-node", URI: "kryptonid://acme-corp/service/root"},
				{Name: "segment1", URI: "kryptonid://acme-corp/service/segment1"},
				{Name: "extra-segment", URI: "kryptonid://acme-corp/service/extra-segment"},
			},
			wantErr: nil, // Extra identities are allowed; only missing ones are an error.
		},
		{
			name: "empty identities list",
			cfg: &config.RootConfig{
				Name: "root-node",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{Name: "segment1"},
					},
				},
			},
			identities: config.Identities{},
			wantErr:    config.ErrInvalidIdentities,
		},
		{
			name: "nil identities list",
			cfg: &config.RootConfig{
				Name: "root-node",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{Name: "segment1"},
					},
				},
			},
			identities: nil,
			wantErr:    config.ErrInvalidIdentities,
		},
		{
			name: "missing root identity",
			cfg: &config.RootConfig{
				Name: "root-node",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{Name: "segment1"},
					},
				},
			},
			identities: config.Identities{
				{Name: "segment1", URI: "kryptonid://acme-corp/service/segment1"},
			},
			wantErr: config.ErrInvalidIdentities,
		},
		{
			name: "duplicate identity names",
			cfg: &config.RootConfig{
				Name: "root-node",
				Topology: spec.Topology{
					Segments: []spec.TopologySegment{
						{Name: "segment1"},
					},
				},
			},
			identities: config.Identities{
				{Name: "root-node", URI: "kryptonid://acme-corp/service/root"},
				{Name: "segment1", URI: "kryptonid://acme-corp/service/segment1"},
				{Name: "segment1", URI: "kryptonid://acme-corp/service/segment1-duplicate"},
			},
			wantErr: config.ErrInvalidIdentities,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.identities.ValidateAuthIdentities(tt.cfg)

			// then
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
