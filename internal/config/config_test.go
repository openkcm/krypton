package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func validRootConfig() *RootConfig {
	return &RootConfig{
		Name: "root",
		Role: "root",
		Segment: spec.HierarchySegment{
			StartKind: "K0",
			EndKind:   "K1",
		},
		SelectorLabels: spec.SelectorLabels{"env": "prod"},
		KeyBindings: map[string]spec.KeyBinding{
			"K0": {
				Vault: spec.VaultSpec{Name: "v", Type: "aws-kms"},
			},
			"K1": {
				Vault:             spec.VaultSpec{Name: "v2", Type: "open-bao"},
				ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"},
			},
		},
		Hierarchy: spec.KeyHierarchy{
			Name: "h",
			KeySpecs: []spec.KeySpec{
				{
					Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: spec.KeyAlgorithmAES256,
					LabelSpecs: spec.LabelSpecs{AllowUserLabels: true},
				},
				{
					Kind: "K1", Role: spec.KeyRoleDek, Algorithm: spec.KeyAlgorithmAES256,
					LabelSpecs: spec.LabelSpecs{
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
	}
}

func validAgentBootstrapConfig() *AgentBootstrapConfig {
	return &AgentBootstrapConfig{
		Name: "agent-aws",
		Role: "agent",
		KryptonRoot: KryptonRoot{
			Address: Address{Type: AddressTypeHTTP, URL: "https://root:8443"},
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
		modify  func(*RootConfig)
		wantErr error
	}{
		{
			name:    "valid config",
			modify:  func(_ *RootConfig) {},
			wantErr: nil,
		},
		{
			name:    "empty name",
			modify:  func(c *RootConfig) { c.Name = "" },
			wantErr: ErrConfigNameEmpty,
		},
		{
			name:    "wrong role",
			modify:  func(c *RootConfig) { c.Role = "agent" },
			wantErr: ErrRoleInvalid,
		},
		{
			name:    "invalid hierarchy",
			modify:  func(c *RootConfig) { c.Hierarchy.Name = "" },
			wantErr: spec.ErrKeyHierarchyNameEmpty,
		},
		{
			name: "invalid topology segment",
			modify: func(c *RootConfig) {
				c.Topology = spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name: "",
							Segment: spec.HierarchySegment{
								StartKind: "K2",
								EndKind:   "K3",
							},
							KeyBindings: map[string]spec.KeyBinding{
								"K2": {Vault: spec.VaultSpec{Name: "v", Type: "t"}},
							},
						},
					},
				}
			},
			wantErr: spec.ErrAgentNameEmpty,
		},
		{
			name: "invalid LabelSpec in hierarchy",
			modify: func(c *RootConfig) {
				c.Hierarchy.KeySpecs[0].LabelSpecs = spec.LabelSpecs{
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
			modify:  func(c *RootConfig) { c.Segment.StartKind = "" },
			wantErr: spec.ErrStartKindEmpty,
		},
		{
			name:    "empty key bindings",
			modify:  func(c *RootConfig) { c.KeyBindings = map[string]spec.KeyBinding{} },
			wantErr: ErrConfigKeyBindingsEmpty,
		},
		{
			name:    "nil key bindings",
			modify:  func(c *RootConfig) { c.KeyBindings = nil },
			wantErr: ErrConfigKeyBindingsEmpty,
		},
		{
			name:    "empty topology is valid",
			modify:  func(c *RootConfig) { c.Topology = spec.Topology{} },
			wantErr: nil,
		},
		{
			name: "cross-validation: root start not hierarchy first key",
			modify: func(c *RootConfig) {
				c.Hierarchy = spec.KeyHierarchy{
					Name: "h",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K2", Role: spec.KeyRoleDek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
					},
				}
				c.Segment = spec.HierarchySegment{StartKind: "K1", EndKind: "K2"}
				c.KeyBindings = map[string]spec.KeyBinding{
					"K1": {Vault: spec.VaultSpec{Name: "v", Type: "t"}},
					"K2": {Vault: spec.VaultSpec{Name: "v2", Type: "t"}},
				}
				c.Topology = spec.Topology{}
			},
			wantErr: spec.ErrRootSegmentStartNotFirst,
		},
		{
			name: "cross-validation: root end kind is tek",
			modify: func(c *RootConfig) {
				c.Hierarchy = spec.KeyHierarchy{
					Name: "h",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K1", Role: spec.KeyRoleTek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K2", Role: spec.KeyRoleDek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
					},
				}
				c.Segment = spec.HierarchySegment{StartKind: "K0", EndKind: "K1"}
				c.KeyBindings = map[string]spec.KeyBinding{
					"K0": {Vault: spec.VaultSpec{Name: "v", Type: "t"}},
					"K1": {Vault: spec.VaultSpec{Name: "v2", Type: "t"}},
				}
				c.Topology = spec.Topology{}
			},
			wantErr: spec.ErrRootSegmentEndIsTek,
		},
		{
			name: "cross-validation: agent start not tek",
			modify: func(c *RootConfig) {
				c.Hierarchy = spec.KeyHierarchy{
					Name: "h",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K2", Role: spec.KeyRoleDek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
					},
				}
				c.Segment = spec.HierarchySegment{StartKind: "K0", EndKind: "K1"}
				c.KeyBindings = map[string]spec.KeyBinding{
					"K0": {Vault: spec.VaultSpec{Name: "v", Type: "t"}},
					"K1": {Vault: spec.VaultSpec{Name: "v2", Type: "t"}, ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				}
				c.Topology = spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name:    "agent-bad",
							Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K2"}, // K2 is dek, not tek
							KeyBindings: map[string]spec.KeyBinding{
								"K2": {Vault: spec.VaultSpec{Name: "v", Type: "t"}, ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
							},
						},
					},
				}
			},
			wantErr: spec.ErrAgentSegmentStartNotTek,
		},
		{
			name: "cross-validation: valid full config with topology",
			modify: func(c *RootConfig) {
				c.Hierarchy = spec.KeyHierarchy{
					Name: "h",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
						{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: spec.KeyAlgorithmAES256, LabelSpecs: validLabelSpec()},
					},
				}
				c.Segment = spec.HierarchySegment{StartKind: "K0", EndKind: "K1"}
				c.KeyBindings = map[string]spec.KeyBinding{
					"K0": {Vault: spec.VaultSpec{Name: "v", Type: "t"}},
					"K1": {Vault: spec.VaultSpec{Name: "v2", Type: "t"}, ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				}
				c.Topology = spec.Topology{
					Segments: []spec.TopologySegment{
						{
							Name:    "agent-aws",
							Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K3"},
							KeyBindings: map[string]spec.KeyBinding{
								"K2": {Vault: spec.VaultSpec{Name: "v", Type: "t"}, ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
								"K3": {Vault: spec.VaultSpec{Name: "v2", Type: "t"}},
							},
						},
					},
				}
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
		modify  func(*AgentBootstrapConfig)
		wantErr error
	}{
		{
			name:    "valid config",
			modify:  func(_ *AgentBootstrapConfig) {},
			wantErr: nil,
		},
		{
			name:    "empty name",
			modify:  func(c *AgentBootstrapConfig) { c.Name = "" },
			wantErr: ErrConfigNameEmpty,
		},
		{
			name:    "wrong role",
			modify:  func(c *AgentBootstrapConfig) { c.Role = "root" },
			wantErr: ErrRoleInvalid,
		},
		{
			name:    "empty address URL",
			modify:  func(c *AgentBootstrapConfig) { c.KryptonRoot.Address.URL = "" },
			wantErr: ErrConfigAddressEmpty,
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
    vault:
      name: "root-hsm-vault"
      type: "open-bao"
  K1:
    vault:
      name: "root-vault"
      type: "open-bao"
    parent_key_provider:
      agent_name: "root"
hierarchy:
  name: "production-hierarchy"
  key_specs:
    - kind: "K0"
      role: "root"
      algorithm: "AES256"
      label_specs:
        allow_user_labels: true
    - kind: "K1"
      role: "kek"
      algorithm: "AES256"
      label_specs:
        allow_user_labels: true
    - kind: "K2"
      role: "tek"
      algorithm: "AES256"
      label_specs:
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
      label_specs:
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
          vault:
            name: "aws-vault"
            type: "open-bao"
          parent_key_provider:
            agent_name: "root"
        K3:
          vault:
            name: "aws-dek-vault"
            type: "in-memory"
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
		validate   func(*testing.T, *RootConfig)
	}{
		{
			name: "valid root config",
			yaml: validYAML,
			validate: func(t *testing.T, cfg *RootConfig) {
				t.Helper()
				assert.Equal(t, "root", cfg.Name)
				assert.Equal(t, spec.AgentRole("root"), cfg.Role)
				assert.Equal(t, "K0", cfg.Segment.StartKind)
				assert.Equal(t, "K1", cfg.Segment.EndKind)
				assert.Equal(t, "production", cfg.SelectorLabels["environment"])
				assert.Len(t, cfg.KeyBindings, 2)
				assert.Equal(t, "root-hsm-vault", cfg.KeyBindings["K0"].Vault.Name)
				assert.Equal(t, "root-vault", cfg.KeyBindings["K1"].Vault.Name)
				assert.Equal(t, "root", cfg.KeyBindings["K1"].ParentKeyProvider.AgentName)
				assert.Equal(t, "production-hierarchy", cfg.Hierarchy.Name)
				assert.Len(t, cfg.Hierarchy.KeySpecs, 4)
				assert.Equal(t, spec.KeyKind("K0"), cfg.Hierarchy.KeySpecs[0].Kind)
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
    vault:
      name: "vault"
      type: "open-bao"
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

			cfg, err := LoadRootConfig(path)
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
		cfg, err := LoadRootConfig("/nonexistent/path.yaml")
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
		validate   func(*testing.T, *AgentBootstrapConfig)
	}{
		{
			name: "valid bootstrap config",
			yaml: validYAML,
			validate: func(t *testing.T, cfg *AgentBootstrapConfig) {
				t.Helper()
				assert.Equal(t, "agent-aws", cfg.Name)
				assert.Equal(t, spec.AgentRole("agent"), cfg.Role)
				assert.Equal(t, AddressTypeHTTP, cfg.KryptonRoot.Address.Type)
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

			cfg, err := LoadAgentBootstrapConfig(path)
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
		cfg, err := LoadAgentBootstrapConfig("/nonexistent/path.yaml")
		assert.Error(t, err)
		assert.Nil(t, cfg)
		assert.Contains(t, err.Error(), "failed to read file")
	})
}

func validLabelSpec() spec.LabelSpecs {
	return spec.LabelSpecs{
		AllowUserLabels: true,
	}
}
