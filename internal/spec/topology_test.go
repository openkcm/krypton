package spec

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func TestValidateHierarchySegment(t *testing.T) {
	tests := []struct {
		name    string
		segment HierarchySegment
		wantErr error
	}{
		{
			name: "valid segment",
			segment: HierarchySegment{
				StartKind: "K2",
				EndKind:   "K3",
			},
			wantErr: nil,
		},
		{
			name: "same start and end kind",
			segment: HierarchySegment{
				StartKind: "K4",
				EndKind:   "K4",
			},
			wantErr: nil,
		},
		{
			name: "empty start kind",
			segment: HierarchySegment{
				StartKind: "",
				EndKind:   "K3",
			},
			wantErr: ErrStartKindEmpty,
		},
		{
			name: "empty end kind",
			segment: HierarchySegment{
				StartKind: "K2",
				EndKind:   "",
			},
			wantErr: ErrEndKindEmpty,
		},
		{
			name: "both empty",
			segment: HierarchySegment{
				StartKind: "",
				EndKind:   "",
			},
			wantErr: ErrStartKindEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.segment.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestValidateKeyBinding(t *testing.T) {
	tests := []struct {
		name    string
		binding KeyBinding
		wantErr error
	}{
		{
			name: "valid binding with all fields",
			binding: KeyBinding{
				Vault: VaultSpec{
					Name: "my-vault",
					Type: "aws-kms",
				},
				ParentKeyProvider: &ParentKeyProviderRef{
					AgentName: "root",
				},
			},
			wantErr: nil,
		},
		{
			name: "valid binding without parent key provider",
			binding: KeyBinding{
				Vault: VaultSpec{
					Name: "my-vault",
					Type: "open-bao",
				},
			},
			wantErr: nil,
		},
		{
			name: "missing vault configuration",
			binding: KeyBinding{
				Vault: VaultSpec{},
			},
			wantErr: ErrVaultConfigMissing,
		},
		{
			name: "empty vault name",
			binding: KeyBinding{
				Vault: VaultSpec{
					Name: "",
					Type: "aws-kms",
				},
			},
			wantErr: ErrVaultNameEmpty,
		},
		{
			name: "empty vault type",
			binding: KeyBinding{
				Vault: VaultSpec{
					Name: "my-vault",
					Type: "",
				},
			},
			wantErr: ErrVaultTypeEmpty,
		},
		{
			name: "empty parent key provider agent name",
			binding: KeyBinding{
				Vault: VaultSpec{
					Name: "my-vault",
					Type: "aws-kms",
				},
				ParentKeyProvider: &ParentKeyProviderRef{
					AgentName: "",
				},
			},
			wantErr: ErrParentKeyProviderAgentEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.binding.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTopologySegment(t *testing.T) {
	validKeyBindings := map[string]KeyBinding{
		"K2": {
			Vault: VaultSpec{
				Name: "vault-k2",
				Type: "aws-kms",
			},
		},
	}

	tests := []struct {
		name    string
		segment TopologySegment
		wantErr error
	}{
		{
			name: "valid topology segment",
			segment: TopologySegment{
				Name: "agent-aws",
				Segment: HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings:    validKeyBindings,
				SelectorLabels: SelectorLabels{"cloud": "aws"},
			},
			wantErr: nil,
		},
		{
			name: "valid topology segment without labels",
			segment: TopologySegment{
				Name: "agent-gcp",
				Segment: HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: validKeyBindings,
			},
			wantErr: nil,
		},
		{
			name: "empty agent name",
			segment: TopologySegment{
				Name: "",
				Segment: HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: validKeyBindings,
			},
			wantErr: ErrAgentNameEmpty,
		},
		{
			name: "invalid hierarchy segment - empty start",
			segment: TopologySegment{
				Name: "agent-aws",
				Segment: HierarchySegment{
					StartKind: "",
					EndKind:   "K3",
				},
				KeyBindings: validKeyBindings,
			},
			wantErr: ErrStartKindEmpty,
		},
		{
			name: "invalid hierarchy segment - empty end",
			segment: TopologySegment{
				Name: "agent-aws",
				Segment: HierarchySegment{
					StartKind: "K2",
					EndKind:   "",
				},
				KeyBindings: validKeyBindings,
			},
			wantErr: ErrEndKindEmpty,
		},
		{
			name: "empty key bindings",
			segment: TopologySegment{
				Name: "agent-aws",
				Segment: HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: map[string]KeyBinding{},
			},
			wantErr: ErrKeyBindingsEmpty,
		},
		{
			name: "nil key bindings",
			segment: TopologySegment{
				Name: "agent-aws",
				Segment: HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: nil,
			},
			wantErr: ErrKeyBindingsEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.segment.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestValidateTopology(t *testing.T) {
	validKeyBindings := map[string]KeyBinding{
		"K2": {
			Vault: VaultSpec{
				Name: "vault-k2",
				Type: "aws-kms",
			},
		},
	}

	tests := []struct {
		name     string
		topology Topology
		wantErr  error
	}{
		{
			name:     "empty topology (0 agents) is valid",
			topology: Topology{},
			wantErr:  nil,
		},
		{
			name: "nil segments is valid",
			topology: Topology{
				Segments: nil,
			},
			wantErr: nil,
		},
		{
			name: "valid single segment",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "agent-aws",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: validKeyBindings,
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "valid multiple segments",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "agent-aws",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: validKeyBindings,
					},
					{
						Name: "agent-gcp",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: validKeyBindings,
					},
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid segment with empty agent name",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: validKeyBindings,
					},
				},
			},
			wantErr: ErrAgentNameEmpty,
		},
		{
			name: "invalid segment with empty key bindings at index 1",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "agent-aws",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: validKeyBindings,
					},
					{
						Name: "agent-gcp",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: map[string]KeyBinding{},
					},
				},
			},
			wantErr: ErrKeyBindingsEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.topology.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, tt.wantErr)
			}
		})
	}
}

func TestVaultSpecUnMarshalYaml(t *testing.T) {
	t.Run("unmarshal in-memory vault config", func(t *testing.T) {
		// given
		a := VaultSpec{
			Name: "my-vault",
			Type: VaultTypeInMemory,
			Config: &InMemoryConfig{
				Prefix: "my-prefix",
			},
		}

		b, _ := yaml.Marshal(a)

		var vaultSpec VaultSpec

		// when
		err := yaml.Unmarshal(b, &vaultSpec)

		// then
		assert.NoError(t, err)
		assert.Equal(t, "my-vault", vaultSpec.Name)
		assert.Equal(t, VaultTypeInMemory, vaultSpec.Type)

		inMemConfig, ok := vaultSpec.Config.(*InMemoryConfig)
		assert.True(t, ok)
		assert.Equal(t, "my-prefix", inMemConfig.Prefix)
	})

	t.Run("unmarshal open-bao vault config", func(t *testing.T) {
		// given
		a := VaultSpec{
			Name: "my-vault",
			Type: VaultTypeOpenBAO,
			Config: &OpenBAOConfig{
				ClusterAddress: "https://bao.example.com",
			},
		}

		b, _ := yaml.Marshal(a)

		var vaultSpec VaultSpec

		// when
		err := yaml.Unmarshal(b, &vaultSpec)

		// then
		assert.NoError(t, err)
		assert.Equal(t, "my-vault", vaultSpec.Name)
		assert.Equal(t, VaultTypeOpenBAO, vaultSpec.Type)

		openBaoConfig, ok := vaultSpec.Config.(*OpenBAOConfig)
		assert.True(t, ok)
		assert.Equal(t, "https://bao.example.com", openBaoConfig.ClusterAddress)
	})

	t.Run("unmarshal with missing config", func(t *testing.T) {
		// given
		a := VaultSpec{
			Name: "my-vault",
			Type: VaultTypeOpenBAO,
		}

		b, _ := yaml.Marshal(a)

		var vaultSpec VaultSpec

		// when
		err := yaml.Unmarshal(b, &vaultSpec)

		// then
		assert.NoError(t, err)
		assert.Equal(t, "my-vault", vaultSpec.Name)
		assert.Equal(t, VaultTypeOpenBAO, vaultSpec.Type)
		assert.Equal(t, &OpenBAOConfig{}, vaultSpec.Config)
	})

	t.Run("unmarshal with unknown vault type", func(t *testing.T) {
		// given
		a := VaultSpec{
			Name: "my-vault",
			Type: "unknown-type",
		}

		b, _ := yaml.Marshal(a)

		var vaultSpec VaultSpec

		// when
		err := yaml.Unmarshal(b, &vaultSpec)

		// then
		assert.Error(t, err)
	})

	t.Run("unmarshal with invalid config type", func(t *testing.T) {
		// given
		a := VaultSpec{
			Name: "my-vault",
			Type: VaultTypeOpenBAO,
			Config: &InMemoryConfig{
				Prefix: "my-prefix",
			},
		}

		b, _ := yaml.Marshal(a)

		var vaultSpec VaultSpec

		// when
		err := yaml.Unmarshal(b, &vaultSpec)

		// then
		assert.NoError(t, err)
	})

	t.Run("unmarshal with invalid config structure", func(t *testing.T) {
		// given
		yamlData := `
name: my-vault
type: open-bao
config:
	unexpected_field: value
`
		var vaultSpec VaultSpec

		// when
		err := yaml.Unmarshal([]byte(yamlData), &vaultSpec)

		// then
		assert.Error(t, err)
	})

	t.Run("unmarshal with missing config field for open-bao", func(t *testing.T) {
		// given
		yamlData := `
name: my-vault
type: open-bao
config:
`
		var vaultSpec VaultSpec

		// when
		err := yaml.Unmarshal([]byte(yamlData), &vaultSpec)

		// then
		assert.NoError(t, err)
		assert.Equal(t, "my-vault", vaultSpec.Name)
		assert.Equal(t, VaultTypeOpenBAO, vaultSpec.Type)

		openBaoConfig, ok := vaultSpec.Config.(*OpenBAOConfig)
		assert.True(t, ok)
		assert.Empty(t, openBaoConfig.ClusterAddress)
	})

	t.Run("should return error if the vault type is unknown", func(t *testing.T) {
		// given
		yamlData := `
name: my-vault
type: unknown-type
config:
`
		var vaultSpec VaultSpec

		// when
		err := yaml.Unmarshal([]byte(yamlData), &vaultSpec)

		// then
		assert.Error(t, err)
	})
}

func TestDeriveSubAgents(t *testing.T) {
	tests := []struct {
		name            string
		topology        Topology
		expSegSubAgents map[string][]string // segment name -> expected sub-agents
	}{
		{
			name:            "empty topology",
			topology:        Topology{},
			expSegSubAgents: map[string][]string{},
		},
		{
			name: "single agent with root as parent",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "agent-aws",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: map[string]KeyBinding{
							"K2": {
								Vault:             VaultSpec{Name: "v", Type: "t"},
								ParentKeyProvider: &ParentKeyProviderRef{AgentName: "root"},
							},
						},
					},
				},
			},
			expSegSubAgents: map[string][]string{
				"agent-aws": nil,
			},
		},
		{
			name: "chain: root -> agent-aws -> agent-leaf",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "agent-aws",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: map[string]KeyBinding{
							"K2": {
								Vault:             VaultSpec{Name: "v", Type: "t"},
								ParentKeyProvider: &ParentKeyProviderRef{AgentName: "root"},
							},
						},
					},
					{
						Name: "agent-leaf",
						Segment: HierarchySegment{
							StartKind: "K4",
							EndKind:   "K4",
						},
						KeyBindings: map[string]KeyBinding{
							"K4": {
								Vault:             VaultSpec{Name: "v", Type: "t"},
								ParentKeyProvider: &ParentKeyProviderRef{AgentName: "agent-aws"},
							},
						},
					},
				},
			},
			expSegSubAgents: map[string][]string{
				"agent-aws":  {"agent-leaf"},
				"agent-leaf": nil,
			},
		},
		{
			name: "multiple sub-agents for root",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "agent-aws",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: map[string]KeyBinding{
							"K2": {
								Vault:             VaultSpec{Name: "v", Type: "t"},
								ParentKeyProvider: &ParentKeyProviderRef{AgentName: "root"},
							},
						},
					},
					{
						Name: "agent-gcp",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: map[string]KeyBinding{
							"K2": {
								Vault:             VaultSpec{Name: "v", Type: "t"},
								ParentKeyProvider: &ParentKeyProviderRef{AgentName: "root"},
							},
						},
					},
				},
			},
			expSegSubAgents: map[string][]string{
				"agent-aws": nil,
				"agent-gcp": nil,
			},
		},
		{
			name: "multiple bindings referencing same parent should not duplicate",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "agent-multi",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: map[string]KeyBinding{
							"K2": {
								Vault:             VaultSpec{Name: "v", Type: "t"},
								ParentKeyProvider: &ParentKeyProviderRef{AgentName: "root"},
							},
							"K3": {
								Vault:             VaultSpec{Name: "v", Type: "t"},
								ParentKeyProvider: &ParentKeyProviderRef{AgentName: "root"},
							},
						},
					},
				},
			},
			expSegSubAgents: map[string][]string{
				"agent-multi": nil,
			},
		},
		{
			name: "binding without parent key provider",
			topology: Topology{
				Segments: []TopologySegment{
					{
						Name: "agent-no-parent",
						Segment: HierarchySegment{
							StartKind: "K2",
							EndKind:   "K2",
						},
						KeyBindings: map[string]KeyBinding{
							"K2": {
								Vault: VaultSpec{Name: "v", Type: "t"},
								// no ParentKeyProvider
							},
						},
					},
				},
			},
			expSegSubAgents: map[string][]string{
				"agent-no-parent": nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			tt.topology.DeriveSubAgents()

			// then
			for _, seg := range tt.topology.Segments {
				exp := tt.expSegSubAgents[seg.Name]
				assert.ElementsMatch(t, exp, seg.SubAgents, "sub-agents mismatch for segment %s", seg.Name)
			}
		})
	}
}
