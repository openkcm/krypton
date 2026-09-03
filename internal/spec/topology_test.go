package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
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

func TestValidateHierarchySegment(t *testing.T) {
	tests := []struct {
		name    string
		segment spec.HierarchySegment
		wantErr error
	}{
		{
			name: "valid segment",
			segment: spec.HierarchySegment{
				StartKind: "K2",
				EndKind:   "K3",
			},
			wantErr: nil,
		},
		{
			name: "same start and end kind",
			segment: spec.HierarchySegment{
				StartKind: "K4",
				EndKind:   "K4",
			},
			wantErr: nil,
		},
		{
			name: "empty start kind",
			segment: spec.HierarchySegment{
				StartKind: "",
				EndKind:   "K3",
			},
			wantErr: spec.ErrStartKindEmpty,
		},
		{
			name: "empty end kind",
			segment: spec.HierarchySegment{
				StartKind: "K2",
				EndKind:   "",
			},
			wantErr: spec.ErrEndKindEmpty,
		},
		{
			name: "both empty",
			segment: spec.HierarchySegment{
				StartKind: "",
				EndKind:   "",
			},
			wantErr: spec.ErrStartKindEmpty,
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
		binding spec.KeyBinding
		wantErr error
	}{
		{
			name: "valid binding with cryptor and all fields",
			binding: spec.KeyBinding{
				CryptorSpec: validCryptorSpec(),
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
				},
				ParentKeyProvider: &spec.ParentKeyProviderRef{
					AgentName: "root",
				},
			},
			wantErr: nil,
		},
		{
			name: "valid binding with sealer only",
			binding: spec.KeyBinding{
				SealerSpec: validSealerSpec(),
			},
			wantErr: nil,
		},
		{
			name: "valid binding with both sealer and cryptor",
			binding: spec.KeyBinding{
				SealerSpec:  validSealerSpec(),
				CryptorSpec: validCryptorSpec(),
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
				},
			},
			wantErr: nil,
		},
		{
			name: "valid binding without parent key provider",
			binding: spec.KeyBinding{
				CryptorSpec: validCryptorSpec(),
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
				},
			},
			wantErr: nil,
		},
		{
			name: "valid binding with cryptor spec only (no vault)",
			binding: spec.KeyBinding{
				CryptorSpec: validCryptorSpec(),
			},
			wantErr: nil,
		},
		{
			name: "missing both sealer and cryptor",
			binding: spec.KeyBinding{
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
				},
			},
			wantErr: spec.ErrBindingMissingSealerOrCryptor,
		},
		{
			name: "empty cryptor spec name",
			binding: spec.KeyBinding{
				CryptorSpec: &cryptorprovider.Spec{
					Name:   "",
					Type:   aes256gcm.TypeAES256GCM,
					Config: &aes256gcm.Config{},
				},
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
				},
			},
			wantErr: cryptorprovider.ErrCryptorNameEmpty,
		},
		{
			name: "empty sealer spec name",
			binding: spec.KeyBinding{
				SealerSpec: &sealerprovider.Spec{
					Name: "",
					Type: staticsecret.TypeStaticSecret,
					Config: &staticsecret.Config{
						Secret: secretprovider.Spec{
							Type:   envvar.Type,
							Config: &envvar.Config{Name: "TEST_KEY"},
						},
					},
				},
			},
			wantErr: sealerprovider.ErrSealerNameEmpty,
		},
		{
			name: "empty vault name",
			binding: spec.KeyBinding{
				CryptorSpec: validCryptorSpec(),
				VaultSpec: &vaultprovider.Spec{
					Name: "",
					Type: sqlitevault.TypeUnsafeMemory,
				},
			},
			wantErr: vaultprovider.ErrVaultNameEmpty,
		},
		{
			name: "empty vault type",
			binding: spec.KeyBinding{
				CryptorSpec: validCryptorSpec(),
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: "",
				},
			},
			wantErr: vault.ErrUnknownType,
		},
		{
			name: "empty parent key provider agent name",
			binding: spec.KeyBinding{
				CryptorSpec: validCryptorSpec(),
				VaultSpec: &vaultprovider.Spec{
					Name: "my-vault",
					Type: sqlitevault.TypeUnsafeMemory,
				},
				ParentKeyProvider: &spec.ParentKeyProviderRef{
					AgentName: "",
				},
			},
			wantErr: spec.ErrParentKeyProviderAgentEmpty,
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
	validKeyBindings := map[string]spec.KeyBinding{
		"K2": {
			CryptorSpec: validCryptorSpec(),
			VaultSpec: &vaultprovider.Spec{
				Name: "vault-k2",
				Type: sqlitevault.TypeUnsafeMemory,
			},
		},
	}

	tests := []struct {
		name    string
		segment spec.TopologySegment
		wantErr error
	}{
		{
			name: "valid topology segment",
			segment: spec.TopologySegment{
				Name: "agent-aws",
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings:    validKeyBindings,
				SelectorLabels: spec.SelectorLabels{"cloud": "aws"},
			},
			wantErr: nil,
		},
		{
			name: "valid topology segment without labels",
			segment: spec.TopologySegment{
				Name: "agent-gcp",
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: validKeyBindings,
			},
			wantErr: nil,
		},
		{
			name: "empty agent name",
			segment: spec.TopologySegment{
				Name: "",
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: validKeyBindings,
			},
			wantErr: spec.ErrAgentNameEmpty,
		},
		{
			name: "invalid hierarchy segment - empty start",
			segment: spec.TopologySegment{
				Name: "agent-aws",
				Segment: spec.HierarchySegment{
					StartKind: "",
					EndKind:   "K3",
				},
				KeyBindings: validKeyBindings,
			},
			wantErr: spec.ErrStartKindEmpty,
		},
		{
			name: "invalid hierarchy segment - empty end",
			segment: spec.TopologySegment{
				Name: "agent-aws",
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "",
				},
				KeyBindings: validKeyBindings,
			},
			wantErr: spec.ErrEndKindEmpty,
		},
		{
			name: "empty key bindings",
			segment: spec.TopologySegment{
				Name: "agent-aws",
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: map[string]spec.KeyBinding{},
			},
			wantErr: spec.ErrKeyBindingsEmpty,
		},
		{
			name: "nil key bindings",
			segment: spec.TopologySegment{
				Name: "agent-aws",
				Segment: spec.HierarchySegment{
					StartKind: "K2",
					EndKind:   "K3",
				},
				KeyBindings: nil,
			},
			wantErr: spec.ErrKeyBindingsEmpty,
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
	validKeyBindings := map[string]spec.KeyBinding{
		"K2": {
			CryptorSpec: validCryptorSpec(),
			VaultSpec: &vaultprovider.Spec{
				Name: "vault-k2",
				Type: sqlitevault.TypeUnsafeMemory,
			},
		},
	}

	tests := []struct {
		name     string
		topology spec.Topology
		wantErr  error
	}{
		{
			name:     "empty topology (0 agents) is valid",
			topology: spec.Topology{},
			wantErr:  nil,
		},
		{
			name: "nil segments is valid",
			topology: spec.Topology{
				Segments: nil,
			},
			wantErr: nil,
		},
		{
			name: "valid single segment",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "agent-aws",
						Segment: spec.HierarchySegment{
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
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "agent-aws",
						Segment: spec.HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: validKeyBindings,
					},
					{
						Name: "agent-gcp",
						Segment: spec.HierarchySegment{
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
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "",
						Segment: spec.HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: validKeyBindings,
					},
				},
			},
			wantErr: spec.ErrAgentNameEmpty,
		},
		{
			name: "invalid segment with empty key bindings at index 1",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "agent-aws",
						Segment: spec.HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: validKeyBindings,
					},
					{
						Name: "agent-gcp",
						Segment: spec.HierarchySegment{
							StartKind: "K2",
							EndKind:   "K3",
						},
						KeyBindings: map[string]spec.KeyBinding{},
					},
				},
			},
			wantErr: spec.ErrKeyBindingsEmpty,
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

func TestChildrenNames(t *testing.T) {
	t.Parallel()

	// given
	tests := []struct {
		name      string
		topology  spec.Topology
		agentName string
		want      map[string]struct{}
		isFound   bool
	}{
		{
			name: "single child found",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "child-1",
						KeyBindings: map[string]spec.KeyBinding{
							"K2": {
								ParentKeyProvider: &spec.ParentKeyProviderRef{
									AgentName: "agent-aws",
								},
							},
						},
					},
				},
			},
			agentName: "agent-aws",
			want:      map[string]struct{}{"child-1": {}},
			isFound:   true,
		},
		{
			name: "multiple children from different segments",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "child-1",
						KeyBindings: map[string]spec.KeyBinding{
							"K1": {
								ParentKeyProvider: &spec.ParentKeyProviderRef{
									AgentName: "agent-aws",
								},
							},
						},
					},
					{
						Name:        "child-2",
						KeyBindings: map[string]spec.KeyBinding{},
					},
					{
						Name: "child-3",
						KeyBindings: map[string]spec.KeyBinding{
							"K3": {
								ParentKeyProvider: &spec.ParentKeyProviderRef{
									AgentName: "agent-aws",
								},
							},
						},
					},
				},
			},
			agentName: "agent-aws",
			want:      map[string]struct{}{"child-1": {}, "child-3": {}},
			isFound:   true,
		},
		{
			name: "no children when bindings have no parent provider",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "child-1",
						KeyBindings: map[string]spec.KeyBinding{
							"K1": {},
						},
					},
					{
						Name:        "child-2",
						KeyBindings: map[string]spec.KeyBinding{},
					},
					{
						Name: "child-3",
						KeyBindings: map[string]spec.KeyBinding{
							"K3": {},
						},
					},
				},
			},
			agentName: "agent-aws",
			want:      nil,
			isFound:   false,
		},
		{
			name: "no children when bindings reference other agents",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "child-1",
						KeyBindings: map[string]spec.KeyBinding{
							"K1": {
								ParentKeyProvider: &spec.ParentKeyProviderRef{
									AgentName: "agent-gcp",
								},
							},
						},
					},
					{
						Name:        "child-2",
						KeyBindings: map[string]spec.KeyBinding{},
					},
					{
						Name: "child-3",
						KeyBindings: map[string]spec.KeyBinding{
							"K3": {
								ParentKeyProvider: &spec.ParentKeyProviderRef{
									AgentName: "agent-azure",
								},
							},
						},
					},
				},
			},
			agentName: "agent-aws",
			want:      nil,
			isFound:   false,
		},
		{
			name: "empty segments slice",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{},
			},
			agentName: "agent-aws",
			want:      nil,
			isFound:   false,
		},
		{
			name: "nil segments slice",
			topology: spec.Topology{
				Segments: nil,
			},
			agentName: "agent-aws",
			want:      nil,
			isFound:   false,
		},
		{
			name: "nil ParentKeyProvider is ignored",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name: "child-1",
						KeyBindings: map[string]spec.KeyBinding{
							"K1": {
								ParentKeyProvider: nil,
							},
						},
					},
				},
			},
			agentName: "agent-aws",
			want:      nil,
			isFound:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// when
			got, ok := tt.topology.ChildrenNames(tt.agentName)

			// then
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.isFound, ok)
		})
	}
}
