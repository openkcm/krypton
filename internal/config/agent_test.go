package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/tlsconf"
)

func TestNewAgentConfig(t *testing.T) {
	// given
	topologySegment := spec.TopologySegment{
		Name:           "segment1",
		SelectorLabels: map[string]string{"region": "us-west"},
		Segment: spec.HierarchySegment{
			StartKind: "K1",
			EndKind:   "K2",
		},
		KeyBindings: map[string]spec.KeyBinding{
			"binding1": {
				CryptorSpec:       validCryptorSpec(),
				ParentKeyProvider: &spec.ParentKeyProviderRef{},
			},
		},
	}
	expHierarchy := spec.KeyHierarchy{
		Name: "some-hierarchy",
		KeySpecs: []spec.KeySpec{
			{
				Kind:      "K1",
				Role:      spec.KeyRoleRoot,
				Algorithm: "",
			},
			{
				Kind:      "K2",
				Role:      spec.KeyRoleDek,
				Algorithm: "",
			},
		},
	}
	expIdentityConfigs := config.IdentityConfigs{
		{
			Name: "root",
			URI:  "root",
		},
	}

	expConfig := config.AgentConfig{
		Name:            "segment1",
		IdentityConfigs: expIdentityConfigs,
		KeyBindings:     topologySegment.KeyBindings,
		Segment:         topologySegment.Segment,
		SelectorLabels:  topologySegment.SelectorLabels,
		Role:            config.AgentRole,
		Hierarchy:       expHierarchy,
		KeepAlive:       30,
	}

	// when
	actConfig := config.NewAgentConfig(expHierarchy, topologySegment, expIdentityConfigs)

	// then
	assert.Equal(t, expConfig, actConfig)
}

func TestValidateAgentBootstrapConfig(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*config.AgentBootstrapConfig)
		wantErr error
	}{
		{
			name:    "valid config",
			modify:  func(_ *config.AgentBootstrapConfig) {},
			wantErr: nil,
		},
		{
			name:    "empty name",
			modify:  func(c *config.AgentBootstrapConfig) { c.Name = "" },
			wantErr: config.ErrConfigNameEmpty,
		},
		{
			name:    "wrong role",
			modify:  func(c *config.AgentBootstrapConfig) { c.Role = "root" },
			wantErr: config.ErrRoleInvalid,
		},
		{
			name:    "empty address URL",
			modify:  func(c *config.AgentBootstrapConfig) { c.KryptonRoot.Address.URL = "" },
			wantErr: config.ErrConfigAddressEmpty,
		},
		{
			name:    "invalid auth type",
			modify:  func(c *config.AgentBootstrapConfig) { c.Auth.AuthType = "invalid" },
			wantErr: config.ErrUnknownAuthType,
		},
		{
			name:    "auth is nil",
			modify:  func(c *config.AgentBootstrapConfig) { c.Auth = nil },
			wantErr: nil,
		},
		{
			name: "address type is not grpc",
			modify: func(c *config.AgentBootstrapConfig) {
				c.KryptonRoot.Address.Type = "http"
			},
			wantErr: config.ErrAddressTypeInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validAgentBootstrapConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestLoadAgentBootstrapConfig(t *testing.T) {
	const validYAML = `name: "agent-aws"
role: "agent"
krypton_root:
  address:
    type: "grpc"
    url: "https://root.krypton.example.com:8443"
`

	tests := []struct {
		name       string
		yaml       string
		wantErr    bool
		errContain string
		validate   func(*testing.T, *config.AgentBootstrapConfig)
	}{
		{
			name: "valid bootstrap config",
			yaml: validYAML,
			validate: func(t *testing.T, cfg *config.AgentBootstrapConfig) {
				t.Helper()
				assert.Equal(t, "agent-aws", cfg.Name)
				assert.Equal(t, config.Role("agent"), cfg.Role)
				assert.Equal(t, config.AddressTypeGRPC, cfg.KryptonRoot.Address.Type)
				assert.Equal(t, "https://root.krypton.example.com:8443", cfg.KryptonRoot.Address.URL)
			},
		},
		{
			name:       "malformed YAML",
			yaml:       "this is: [not valid yaml: {{",
			wantErr:    true,
			errContain: "failed to parse YAML",
		},
		{
			name: "valid YAML but fails validation",
			yaml: `name: ""
role: "agent"
krypton_root:
  address:
    type: "grpc"
    url: "https://root:8443"
`,
			wantErr:    true,
			errContain: "config name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTestFile(t, dir, "config.yaml", tt.yaml)

			cfg, err := config.LoadAgentBootstrapConfig(path)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, cfg)
				if tt.errContain != "" {
					assert.Contains(t, err.Error(), tt.errContain)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
				if tt.validate != nil {
					tt.validate(t, cfg)
				}
			}
		})
	}

	t.Run("file not found", func(t *testing.T) {
		cfg, err := config.LoadAgentBootstrapConfig("/nonexistent/path.yaml")
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "failed to read file")
	})
}

func validAgentBootstrapConfig() *config.AgentBootstrapConfig {
	return &config.AgentBootstrapConfig{
		Name: "agent-aws",
		Role: "agent",
		KryptonRoot: config.KryptonRoot{
			Address: config.Address{Type: config.AddressTypeGRPC, URL: "https://root:8443"},
		},
		Auth: &config.AgentAuthConfig{
			AuthType: config.AuthTypeMTLS,
			Config: &config.MTLSConfig{
				Server: tlsconf.Server{
					CertPath: "certpath",
					KeyPath:  "keypath",
					CAPath:   "capath",
				},
				Client: tlsconf.Client{
					CertPath: "certpath",
					KeyPath:  "keypath",
					CAPath:   "capath",
				},
			},
		},
	}
}
