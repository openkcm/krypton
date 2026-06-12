package spec

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
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
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
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
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
				},
			},
			wantErr: nil,
		},
		{
			name: "empty vault name",
			binding: KeyBinding{
				VaultSpec: &vaultprovider.Spec{
					Name: "",
					Type: sqlitevault.TypeUnsafeMemory,
				},
			},
			wantErr: vaultprovider.ErrVaultNameEmpty,
		},
		{
			name: "empty vault type",
			binding: KeyBinding{
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: "",
				},
			},
			wantErr: vault.ErrUnknownType,
		},
		{
			name: "empty parent key provider agent name",
			binding: KeyBinding{
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
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
			VaultSpec: &vaultprovider.Spec{
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
			VaultSpec: &vaultprovider.Spec{
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
