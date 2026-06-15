package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
)

// testHierarchy returns a 5-key hierarchy: K0(root) → K1(kek) → K2(tek) → K3(kek) → K4(dek)
func testHierarchy() spec.KeyHierarchy {
	return spec.KeyHierarchy{
		Name: "test-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K3", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K4", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
		},
	}
}

func validVault() *vaultprovider.Spec {
	return &vaultprovider.Spec{Name: "v", Type: sqlitevault.TypeUnsafeMemory}
}

func validCryptor() cryptorprovider.Spec {
	return cryptorprovider.Spec{
		Name:   "test-crypto",
		Type:   aes256gcm.TypeAES256GCM,
		Config: &aes256gcm.Config{},
	}
}

func TestValidateSegmentAgainstHierarchy(t *testing.T) {
	h := testHierarchy()

	tests := []struct {
		name     string
		seg      spec.HierarchySegment
		bindings map[string]spec.KeyBinding
		wantErr  error
	}{
		{
			name: "valid segment K0-K2 with correct bindings",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K2"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: nil,
		},
		{
			name: "valid single-key segment",
			seg:  spec.HierarchySegment{StartKind: "K2", EndKind: "K2"},
			bindings: map[string]spec.KeyBinding{
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: nil,
		},
		{
			name: "start kind not in hierarchy",
			seg:  spec.HierarchySegment{StartKind: "UNKNOWN", EndKind: "K2"},
			bindings: map[string]spec.KeyBinding{
				"UNKNOWN": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K2":      {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: spec.ErrSegmentStartKindNotInHierarchy,
		},
		{
			name: "end kind not in hierarchy",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "UNKNOWN"},
			bindings: map[string]spec.KeyBinding{
				"K0":      {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"UNKNOWN": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: spec.ErrSegmentEndKindNotInHierarchy,
		},
		{
			name: "start after end in hierarchy order",
			seg:  spec.HierarchySegment{StartKind: "K3", EndKind: "K1"},
			bindings: map[string]spec.KeyBinding{
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: spec.ErrSegmentStartAfterEnd,
		},
		{
			name: "missing binding for key in range",
			seg:  spec.HierarchySegment{StartKind: "K1", EndKind: "K3"},
			bindings: map[string]spec.KeyBinding{
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				// K2 missing
			},
			wantErr: spec.ErrSegmentBindingsMissing,
		},
		{
			name: "extra binding for key outside range",
			seg:  spec.HierarchySegment{StartKind: "K1", EndKind: "K2"},
			bindings: map[string]spec.KeyBinding{
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()}, // outside range
			},
			wantErr: spec.ErrSegmentBindingsExtra,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := spec.ValidateSegmentAgainstHierarchy(h, tt.seg, tt.bindings)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRootSegment(t *testing.T) {
	h := testHierarchy()

	tests := []struct {
		name     string
		seg      spec.HierarchySegment
		bindings map[string]spec.KeyBinding
		wantErr  error
	}{
		{
			name: "valid root segment K0-K1",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K1"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
			},
			wantErr: nil,
		},
		{
			name: "valid root segment covers everything (0-agent deploy)",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K4"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: nil,
		},
		{
			name: "root start not hierarchy first key",
			seg:  spec.HierarchySegment{StartKind: "K1", EndKind: "K2"},
			bindings: map[string]spec.KeyBinding{
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: spec.ErrRootSegmentStartNotFirst,
		},
		{
			name: "root end kind is tek",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K2"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: spec.ErrRootSegmentEndIsTek,
		},
		{
			name: "root key binding has parent key provider",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K1"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "someone"}},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: spec.ErrRootBindingHasParentKeyProvider,
		},
		{
			name: "root end is dek valid for 0-agent deployment",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K4"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: nil,
		},
		{
			name: "non-root key in root segment has parent key provider referencing root is valid",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K1"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
			},
			wantErr: nil,
		},
		{
			name: "root segment with missing binding fails generic check",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K1"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				// K1 missing
			},
			wantErr: spec.ErrSegmentBindingsMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := spec.ValidateRootSegment(h, tt.seg, tt.bindings)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateAgentSegment(t *testing.T) {
	h := testHierarchy()

	tests := []struct {
		name     string
		seg      spec.HierarchySegment
		bindings map[string]spec.KeyBinding
		wantErr  error
	}{
		{
			name: "valid agent segment K2-K4 (tek to dek)",
			seg:  spec.HierarchySegment{StartKind: "K2", EndKind: "K4"},
			bindings: map[string]spec.KeyBinding{
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: nil,
		},
		{
			name: "valid agent segment K2-K3 (tek to kek)",
			seg:  spec.HierarchySegment{StartKind: "K2", EndKind: "K3"},
			bindings: map[string]spec.KeyBinding{
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: nil,
		},
		{
			name: "valid single-key agent segment (tek only)",
			seg:  spec.HierarchySegment{StartKind: "K2", EndKind: "K2"},
			bindings: map[string]spec.KeyBinding{
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
			},
			wantErr: nil,
		},
		{
			name: "agent start kind not tek (kek start)",
			seg:  spec.HierarchySegment{StartKind: "K1", EndKind: "K3"},
			bindings: map[string]spec.KeyBinding{
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: spec.ErrAgentSegmentStartNotTek,
		},
		{
			name: "agent start kind not tek (dek start)",
			seg:  spec.HierarchySegment{StartKind: "K4", EndKind: "K4"},
			bindings: map[string]spec.KeyBinding{
				"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
			},
			wantErr: spec.ErrAgentSegmentStartNotTek,
		},
		{
			name: "agent segment contains root key",
			seg:  spec.HierarchySegment{StartKind: "K0", EndKind: "K1"},
			bindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			// Root key is not tek, so this fails on start-not-tek first
			wantErr: spec.ErrAgentSegmentStartNotTek,
		},
		{
			name: "agent start binding missing parent key provider",
			seg:  spec.HierarchySegment{StartKind: "K2", EndKind: "K4"},
			bindings: map[string]spec.KeyBinding{
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()}, // no ParentKeyProvider
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
			wantErr: spec.ErrAgentSegmentStartMissingParentKeyProvider,
		},
		{
			name: "agent segment with missing binding fails generic check",
			seg:  spec.HierarchySegment{StartKind: "K2", EndKind: "K4"},
			bindings: map[string]spec.KeyBinding{
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				// K3 missing
			},
			wantErr: spec.ErrSegmentBindingsMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := spec.ValidateAgentSegment(h, tt.seg, tt.bindings)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateTopologyAgainstHierarchy(t *testing.T) {
	h := testHierarchy()

	rootSeg := spec.HierarchySegment{StartKind: "K0", EndKind: "K1"}
	rootBindings := map[string]spec.KeyBinding{
		"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
		"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
	}

	validAgentSegment := func(name string) spec.TopologySegment {
		return spec.TopologySegment{
			Name:    name,
			Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K4"},
			KeyBindings: map[string]spec.KeyBinding{
				"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
				"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
			},
		}
	}

	tests := []struct {
		name         string
		topology     spec.Topology
		rootSeg      spec.HierarchySegment
		rootBindings map[string]spec.KeyBinding
		wantErr      error
	}{
		{
			name:         "valid topology with one agent",
			topology:     spec.Topology{Segments: []spec.TopologySegment{validAgentSegment("agent-aws")}},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      nil,
		},
		{
			name:         "empty topology (0 agents) is valid",
			topology:     spec.Topology{},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      nil,
		},
		{
			name: "valid topology with multiple agents sharing same segment",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					validAgentSegment("agent-aws"),
					validAgentSegment("agent-gcp"),
				},
			},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      nil,
		},
		{
			name: "duplicate segment names",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					validAgentSegment("agent-aws"),
					validAgentSegment("agent-aws"),
				},
			},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      spec.ErrTopologyDuplicateSegmentName,
		},
		{
			name: "parent key provider references nonexistent agent",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name:    "agent-aws",
						Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K4"},
						KeyBindings: map[string]spec.KeyBinding{
							"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "nonexistent"}},
							"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
							"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
						},
					},
				},
			},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      spec.ErrParentKeyProviderNotResolvable,
		},
		{
			name: "parent key provider references root is valid",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name:    "agent-aws",
						Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K4"},
						KeyBindings: map[string]spec.KeyBinding{
							"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
							"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
							"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
						},
					},
				},
			},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      nil,
		},
		{
			name: "parent key provider references another topology segment is valid",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name:    "agent-mid",
						Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K3"},
						KeyBindings: map[string]spec.KeyBinding{
							"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
							"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
						},
					},
					{
						Name:    "agent-leaf",
						Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K4"},
						KeyBindings: map[string]spec.KeyBinding{
							"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
							"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
							"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
						},
					},
				},
			},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      nil,
		},
		{
			name: "agent segment fails validation is cascaded",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name:    "agent-bad",
						Segment: spec.HierarchySegment{StartKind: "K1", EndKind: "K3"}, // K1 is kek, not tek
						KeyBindings: map[string]spec.KeyBinding{
							"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
							"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
							"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
						},
					},
				},
			},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      spec.ErrAgentSegmentStartNotTek,
		},
		{
			name: "parent key provider segment does not contain parent key kind",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{
					{
						Name:    "agent-mid",
						Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K3"},
						KeyBindings: map[string]spec.KeyBinding{
							// K2's parent is K1, which is in root segment K0-K1 — referencing agent-leaf which manages K2-K4
							"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "agent-leaf"}},
							"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
						},
					},
					{
						Name:    "agent-leaf",
						Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K4"},
						KeyBindings: map[string]spec.KeyBinding{
							"K2": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"}},
							"K3": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
							"K4": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
						},
					},
				},
			},
			rootSeg:      rootSeg,
			rootBindings: rootBindings,
			wantErr:      spec.ErrParentKeyProviderKeyNotInParentSegment,
		},
		{
			name: "root binding parent key provider references nonexistent agent",
			topology: spec.Topology{
				Segments: []spec.TopologySegment{validAgentSegment("agent-aws")},
			},
			rootSeg: rootSeg,
			rootBindings: map[string]spec.KeyBinding{
				"K0": {CryptorSpec: validCryptor(), VaultSpec: validVault()},
				"K1": {CryptorSpec: validCryptor(), VaultSpec: validVault(), ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "nonexistent"}},
			},
			wantErr: spec.ErrParentKeyProviderNotResolvable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := spec.ValidateTopologyAgainstHierarchy(h, tt.topology, tt.rootSeg, tt.rootBindings)
			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
