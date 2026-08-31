package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/tlsconf"
	"github.com/openkcm/krypton/pkg/model"
)

func validCryptorSpec() *cryptorprovider.Spec {
	return &cryptorprovider.Spec{
		Name:   "test-crypto",
		Type:   aes256gcm.TypeAES256GCM,
		Config: &aes256gcm.Config{},
	}
}

func validSealerSpec() *sealerprovider.Spec {
	return &sealerprovider.Spec{
		Name: "test-sealer",
		Type: staticsecret.TypeStaticSecret,
		Config: &staticsecret.Config{
			Secret: secretprovider.Spec{
				Type:   envvar.Type,
				Config: &envvar.Config{Name: "TEST_KEY"},
			},
		},
	}
}

func validRootConfig() *config.RootConfig {
	return &config.RootConfig{
		Name: "root",
		Role: "root",
		Segment: spec.HierarchySegment{
			StartKind: "K0",
			EndKind:   "K1",
		},
		SelectorLabels: spec.SelectorLabels{"env": "prod"},
		KeyBindings: map[string]spec.KeyBinding{
			"K0": {SealerSpec: validSealerSpec()},
			"K1": {
				CryptorSpec:       validCryptorSpec(),
				ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"},
			},
		},
		Hierarchy: spec.KeyHierarchy{
			Name: "h",
			KeySpecs: []spec.KeySpec{
				{
					Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256,
					LabelsSpec: spec.LabelsSpec{AllowUserLabels: true},
				},
				{
					Kind: "K1", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256,
					LabelsSpec: spec.LabelsSpec{
						Requirements: map[string]spec.LabelRequirement{
							"env": {
								IsRequired: true,
							},
						},
					},
				},
			},
		},
		Topology: spec.Topology{},
		Auth: &config.RootAuthConfig{
			AuthType: config.AuthTypeMTLS,
			Identities: []config.IdentityConfig{
				{
					Name: "root",
					URI:  "kryptonid://acme-service/service/root",
				},
			},
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

func validAgentBootstrapConfig() *config.AgentBootstrapConfig {
	return &config.AgentBootstrapConfig{
		Name: "agent-aws",
		Role: "agent",
		KryptonRoot: config.KryptonRoot{
			Address: config.Address{Type: config.AddressTypeHTTP, URL: "https://root:8443"},
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

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), 0o600)
	assert.NoError(t, err)
	return path
}

func TestValidateRootConfig(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*config.RootConfig)
		wantErr error
	}{
		{
			name:    "valid config",
			modify:  func(_ *config.RootConfig) {},
			wantErr: nil,
		},
		{
			name:    "empty name",
			modify:  func(c *config.RootConfig) { c.Name = "" },
			wantErr: config.ErrConfigNameEmpty,
		},
		{
			name:    "wrong role",
			modify:  func(c *config.RootConfig) { c.Role = "agent" },
			wantErr: config.ErrRoleInvalid,
		},
		{
			name:    "invalid hierarchy",
			modify:  func(c *config.RootConfig) { c.Hierarchy.Name = "" },
			wantErr: spec.ErrKeyHierarchyNameEmpty,
		},
		{
			name: "invalid topology segment",
			modify: func(c *config.RootConfig) {
				c.Topology = spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "",
							Segment: spec.HierarchySegment{
								StartKind: "K2",
								EndKind:   "K3",
							},
							KeyBindings: map[string]spec.KeyBinding{
								"K2": {CryptorSpec: validCryptorSpec()},
							},
						},
					},
				}
			},
			wantErr: spec.ErrAgentNameEmpty,
		},
		{
			name: "invalid LabelsSpec in hierarchy",
			modify: func(c *config.RootConfig) {
				c.Hierarchy.KeySpecs[0].LabelsSpec = spec.LabelsSpec{
					Requirements: map[string]spec.LabelRequirement{
						"env": {
							IsRequired: true,
							Validator: &spec.LabelValidator{
								Type: "invalid",
							},
						},
					},
				}
			},
			wantErr: spec.ErrLabelValidatorInvalidType,
		},
		{
			name:    "invalid segment",
			modify:  func(c *config.RootConfig) { c.Segment.StartKind = "" },
			wantErr: spec.ErrStartKindEmpty,
		},
		{
			name:    "empty key bindings",
			modify:  func(c *config.RootConfig) { c.KeyBindings = map[string]spec.KeyBinding{} },
			wantErr: config.ErrConfigKeyBindingsEmpty,
		},
		{
			name:    "nil key bindings",
			modify:  func(c *config.RootConfig) { c.KeyBindings = nil },
			wantErr: config.ErrConfigKeyBindingsEmpty,
		},
		{
			name:    "empty topology is valid",
			modify:  func(c *config.RootConfig) { c.Topology = spec.Topology{} },
			wantErr: nil,
		},
		{
			name: "cross-validation: root start not hierarchy first key",
			modify: func(c *config.RootConfig) {
				c.Hierarchy = spec.KeyHierarchy{
					Name: "h",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K2", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
					},
				}
				c.Segment = spec.HierarchySegment{StartKind: "K1", EndKind: "K2"}
				c.KeyBindings = map[string]spec.KeyBinding{
					"K1": {CryptorSpec: validCryptorSpec()},
					"K2": {CryptorSpec: validCryptorSpec()},
				}
				c.Topology = spec.Topology{}
			},
			wantErr: spec.ErrRootSegmentStartNotFirst,
		},
		{
			name: "cross-validation: root end kind is tek",
			modify: func(c *config.RootConfig) {
				c.Hierarchy = spec.KeyHierarchy{
					Name: "h",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K1", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K2", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
					},
				}
				c.Segment = spec.HierarchySegment{StartKind: "K0", EndKind: "K1"}
				c.KeyBindings = map[string]spec.KeyBinding{
					"K0": {SealerSpec: validSealerSpec()},
					"K1": {SealerSpec: validSealerSpec(), CryptorSpec: validCryptorSpec()},
				}
				c.Topology = spec.Topology{}
			},
			wantErr: spec.ErrRootSegmentEndIsTek,
		},
		{
			name: "cross-validation: agent start not tek",
			modify: func(c *config.RootConfig) {
				c.Hierarchy = spec.KeyHierarchy{
					Name: "h",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K2", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
					},
				}
				c.Segment = spec.HierarchySegment{StartKind: "K0", EndKind: "K1"}
				c.KeyBindings = map[string]spec.KeyBinding{
					"K0": {SealerSpec: validSealerSpec()},
					"K1": {CryptorSpec: validCryptorSpec(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				}
				c.Topology = spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name:    "agent-bad",
							Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K2"}, // K2 is dek, not tek
							KeyBindings: map[string]spec.KeyBinding{
								"K2": {CryptorSpec: validCryptorSpec(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
							},
						},
					},
				}
			},
			wantErr: spec.ErrAgentSegmentStartNotTek,
		},
		{
			name: "cross-validation: valid full config with topology",
			modify: func(c *config.RootConfig) {
				c.Hierarchy = spec.KeyHierarchy{
					Name: "h",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
						{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256, LabelsSpec: validLabelsSpec()},
					},
				}
				c.Segment = spec.HierarchySegment{StartKind: "K0", EndKind: "K1"}
				c.KeyBindings = map[string]spec.KeyBinding{
					"K0": {SealerSpec: validSealerSpec()},
					"K1": {CryptorSpec: validCryptorSpec(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				}
				c.Topology = spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name:    "agent-aws",
							Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K3"},
							KeyBindings: map[string]spec.KeyBinding{
								"K2": {SealerSpec: validSealerSpec(), CryptorSpec: validCryptorSpec(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
								"K3": {CryptorSpec: validCryptorSpec()},
							},
						},
					},
				}
				c.Auth.Identities = append(c.Auth.Identities, config.IdentityConfig{
					Name: "agent-aws",
					URI:  "kryptonid://acme-service/service/agent-aws",
				})
			},
			wantErr: nil,
		},
		{
			name: "invalid auth type",
			modify: func(c *config.RootConfig) {
				c.Auth = &config.RootAuthConfig{
					AuthType: "invalid",
				}
			},
			wantErr: config.ErrUnknownAuthType,
		},
		{
			name: "auth is nil",
			modify: func(c *config.RootConfig) {
				c.Auth = nil
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validRootConfig()
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

func TestLoadRootConfig(t *testing.T) {
	const validYAML = `name: "root"
role: "root"
segment:
  start_kind: "K0"
  end_kind: "K1"
selector_labels:
  environment: "production"
key_bindings:
  K0:
    sealer:
      name: "root-sealer"
      type: "aes256gcm-staticsecret"
      config:
        secret:
          type: envvar
          config:
            name: KRYPTON_ROOT_KEY
  K1:
    crypto:
      name: "kek-crypto"
      type: "aes256gcm"
    vault:
      name: "root-vault"
      type: "unsafe-sqlite-memory"
    parent_key_provider:
      agent_name: "root"
hierarchy:
  name: "production-hierarchy"
  key_specs:
    - kind: "K0"
      role: "root"
      algorithm: "AES256"
      labels_spec:
        allow_user_labels: true
    - kind: "K1"
      role: "kek"
      algorithm: "AES256"
      labels_spec:
        allow_user_labels: true
    - kind: "K2"
      role: "tek"
      algorithm: "AES256"
      labels_spec:
        allow_user_labels: true
        requirements:
          type:
            is_required: true
            validator:
              type: enum
              params:
                values: "production,staging,development"
    - kind: "K3"
      role: "dek"
      algorithm: "AES256"
      labels_spec:
        allow_user_labels: true
        requirements:
          env:
            is_required: true
            validator:
              type: regex
              params:
                pattern: "^(production|staging|development)$"
topology:
  segments:
    - name: "agent-aws"
      segment:
        start_kind: "K2"
        end_kind: "K3"
      key_bindings:
        K2:
          sealer:
            name: "tek-sealer"
            type: "aes256gcm-staticsecret"
            config:
              secret:
                type: envvar
                config:
                  name: KRYPTON_TEK_KEY
          crypto:
            name: "tek-crypto"
            type: "aes256gcm"
          vault:
            name: "aws-vault"
            type: "unsafe-sqlite-memory"
          parent_key_provider:
            agent_name: "root"
        K3:
          crypto:
            name: "dek-crypto"
            type: "aes256gcm"
          vault:
            name: "aws-dek-vault"
            type: "unsafe-sqlite-memory"
      selector_labels:
        cloud: "aws"
reconciler:
  maxReconcileCount: 7
  targets:
    - name: agent-aws
      address: localhost:9091
`

	tests := []struct {
		name       string
		yaml       string
		wantErr    bool
		errContain string
		validate   func(*testing.T, *config.RootConfig)
	}{
		{
			name: "valid root config",
			yaml: validYAML,
			validate: func(t *testing.T, cfg *config.RootConfig) {
				t.Helper()
				assert.Equal(t, "root", cfg.Name)
				assert.Equal(t, spec.AgentRole("root"), cfg.Role)
				assert.Equal(t, "K0", cfg.Segment.StartKind)
				assert.Equal(t, "K1", cfg.Segment.EndKind)
				assert.Equal(t, "production", cfg.SelectorLabels["environment"])
				assert.Len(t, cfg.KeyBindings, 2)
				assert.Equal(t, "root-sealer", cfg.KeyBindings["K0"].SealerSpec.Name)
				assert.Nil(t, cfg.KeyBindings["K0"].CryptorSpec)
				assert.Equal(t, "root-vault", cfg.KeyBindings["K1"].VaultSpec.Name)
				assert.Equal(t, "root", cfg.KeyBindings["K1"].ParentKeyProvider.AgentName)
				assert.Equal(t, "production-hierarchy", cfg.Hierarchy.Name)
				assert.Len(t, cfg.Hierarchy.KeySpecs, 4)
				assert.Equal(t, model.KeyKind("K0"), cfg.Hierarchy.KeySpecs[0].Kind)
				assert.Len(t, cfg.Topology.Segments, 1)
				assert.Equal(t, "agent-aws", cfg.Topology.Segments[0].Name)
				assert.Equal(t, uint64(7), cfg.Reconciler.MaxReconcileCount)
				assert.Equal(t, "localhost:9091", cfg.Reconciler.Targets[0].Address)
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
role: "root"
segment:
  start_kind: "K0"
  end_kind: "K1"
key_bindings:
  K0:
    crypto:
      name: "test-crypto"
      type: "aes256gcm"
    vault:
      name: "vault"
      type: "unsafe-sqlite-memory"
hierarchy:
  name: "h"
  key_specs:
    - kind: "K0"
      role: "root"
      algorithm: "AES256"
`,
			wantErr:    true,
			errContain: "config name cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := writeTestFile(t, dir, "config.yaml", tt.yaml)

			cfg, err := config.LoadRootConfig(path)
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
		cfg, err := config.LoadRootConfig("/nonexistent/path.yaml")
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "failed to read file")
	})
}

func TestLoadAgentBootstrapConfig(t *testing.T) {
	const validYAML = `name: "agent-aws"
role: "agent"
krypton_root:
  address:
    type: "http"
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
				assert.Equal(t, spec.AgentRole("agent"), cfg.Role)
				assert.Equal(t, config.AddressTypeHTTP, cfg.KryptonRoot.Address.Type)
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
    type: "http"
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

func validLabelsSpec() spec.LabelsSpec {
	return spec.LabelsSpec{
		AllowUserLabels: true,
	}
}
