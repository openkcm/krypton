package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
					Name:   "my-vault",
					Type:   "aws-kms",
					Params: map[string]any{"region": "us-east-1"},
				},
				ParentKeyProvider: &ParentKeyProviderRef{
					AgentName: "root",
				},
				Labels: Labels{"env": "prod"},
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
			name: "valid binding with nil params",
			binding: KeyBinding{
				Vault: VaultSpec{
					Name: "my-vault",
					Type: "gcp-kms",
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
				KeyBindings: validKeyBindings,
				Labels:      Labels{"cloud": "aws"},
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
