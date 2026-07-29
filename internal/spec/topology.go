package spec

import (
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
)

var (
	ErrStartKindEmpty                = errors.New("start kind cannot be empty")
	ErrEndKindEmpty                  = errors.New("end kind cannot be empty")
	ErrParentKeyProviderAgentEmpty   = errors.New("parent key provider agent name cannot be empty")
	ErrAgentNameEmpty                = errors.New("agent name cannot be empty")
	ErrKeyBindingsEmpty              = errors.New("key bindings cannot be empty")
	ErrBindingMissingSealerOrCryptor = errors.New("key binding must have at least a sealer or cryptor")
)

// SelectorLabels is a key-value map for metadata
type SelectorLabels map[string]string

// HierarchySegment represents a contiguous range of key kinds in the hierarchy
type HierarchySegment struct {
	StartKind string `yaml:"start_kind"` // First key kind in segment (e.g., "K2")
	EndKind   string `yaml:"end_kind"`   // Last key kind in segment (e.g., "K3") - inclusive
}

// ParentKeyProviderRef specifies which agent provides parent keys for sealing/unsealing
type ParentKeyProviderRef struct {
	AgentName string `yaml:"agent_name"` // Agent name that provides parent keys
}

// KeyBinding encapsulates all dependencies needed to implement a key kind
type KeyBinding struct {
	SealerSpec        *sealerprovider.Spec  `yaml:"sealer,omitempty"`              // Seals with externally provided secret
	CryptorSpec       *cryptorprovider.Spec `yaml:"crypto,omitempty"`              // Encrypts/decrypts with generated and stored secret
	VaultSpec         *vaultprovider.Spec   `yaml:"vault,omitempty"`               // Storage backend configuration
	ParentKeyProvider *ParentKeyProviderRef `yaml:"parent_key_provider,omitempty"` // Where to get parent keys for sealing/unsealing
}

// TopologySegment defines an agent's portion of the hierarchy
type TopologySegment struct {
	Name           string                `yaml:"name"`         // Agent name (must match cert CN)
	Segment        HierarchySegment      `yaml:"segment"`      // Keys this agent manages
	KeyBindings    map[string]KeyBinding `yaml:"key_bindings"` // All dependencies per key kind (key = kind name)
	SelectorLabels SelectorLabels        `yaml:"selector_labels,omitempty"`
}

// Topology defines the deployment layout
type Topology struct {
	Segments []TopologySegment `yaml:"segments"` // List of agent segments (0 to N agents)
}

func (t *Topology) GetSegemntByName(name string) *TopologySegment {
	for _, seg := range t.Segments {
		if seg.Name == name {
			return &seg
		}
	}

	return nil
}

func (hs *HierarchySegment) Validate() error {
	// NOTE: we dont have key kinds defined yet but when we do we should validate that EndKind > StartKind.
	// So key kind should implement some sort of comparable interface.
	if hs.StartKind == "" {
		return ErrStartKindEmpty
	}
	if hs.EndKind == "" {
		return ErrEndKindEmpty
	}

	return nil
}

func (kb *KeyBinding) Validate() error {
	if kb.SealerSpec == nil && kb.CryptorSpec == nil {
		return ErrBindingMissingSealerOrCryptor
	}

	if kb.SealerSpec != nil {
		if err := kb.SealerSpec.Validate(); err != nil {
			return err
		}
	}

	if kb.CryptorSpec != nil {
		if err := kb.CryptorSpec.Validate(); err != nil {
			return err
		}
	}

	if kb.VaultSpec != nil {
		if err := kb.VaultSpec.Validate(); err != nil {
			return err
		}
	}
	if kb.ParentKeyProvider != nil && kb.ParentKeyProvider.AgentName == "" {
		return ErrParentKeyProviderAgentEmpty
	}

	return nil
}

func (ts *TopologySegment) Validate() error {
	if ts.Name == "" {
		return ErrAgentNameEmpty
	}
	if err := ts.Segment.Validate(); err != nil {
		return err
	}
	if len(ts.KeyBindings) == 0 {
		return ErrKeyBindingsEmpty
	}
	return nil
}

// Validate checks the Topology for structural correctness by validating each segment.
// An empty topology (0 segments) is valid — root can operate alone without agents.
func (t *Topology) Validate() error {
	for i, seg := range t.Segments {
		if err := seg.Validate(); err != nil {
			return fmt.Errorf("segment at index %d: %w", i, err)
		}
	}
	return nil
}
