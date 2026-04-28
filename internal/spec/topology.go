package spec

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"
)

var (
	ErrStartKindEmpty              = errors.New("start kind cannot be empty")
	ErrEndKindEmpty                = errors.New("end kind cannot be empty")
	ErrVaultConfigMissing          = errors.New("vault configuration missing for key binding")
	ErrVaultNameEmpty              = errors.New("vault name cannot be empty")
	ErrVaultTypeEmpty              = errors.New("vault type cannot be empty")
	ErrParentKeyProviderAgentEmpty = errors.New("parent key provider agent name cannot be empty")
	ErrAgentNameEmpty              = errors.New("agent name cannot be empty")
	ErrKeyBindingsEmpty            = errors.New("key bindings cannot be empty")
)

// SelectorLabels is a key-value map for metadata
type SelectorLabels map[string]string

// VaultType defines the type of vault (e.g., "open-bao", "aws-kms", "gcp-kms")
type VaultType string

const (
	VaultTypeInMemory VaultType = "in-memory"
	VaultTypeOpenBAO  VaultType = "open-bao"
)

// HierarchySegment represents a contiguous range of key kinds in the hierarchy
type HierarchySegment struct {
	StartKind string `yaml:"start_kind"` // First key kind in segment (e.g., "K2")
	EndKind   string `yaml:"end_kind"`   // Last key kind in segment (e.g., "K3") - inclusive
}

// ParentKeyProviderRef specifies which agent provides parent keys for unwrapping
type ParentKeyProviderRef struct {
	AgentName string `yaml:"agent_name"` // Agent name that provides parent keys
}

var (
	_ yaml.Unmarshaler = (*VaultSpec)(nil)
	_ yaml.Marshaler   = VaultSpec{}
)

// VaultSpec holds storage backend configuration
type VaultSpec struct {
	Name   string      `yaml:"name"` // Vault identifier
	Type   VaultType   `yaml:"type"` // Vault type (e.g., "open-bao", "aws-kms", "gcp-kms")
	Config VaultConfig `yaml:"-"`    // Decoded vault config (not from YAML)
}

// KeyBinding encapsulates all dependencies needed to implement a key kind
type KeyBinding struct {
	Vault             VaultSpec             `yaml:"vault"`                         // Storage backend configuration
	ParentKeyProvider *ParentKeyProviderRef `yaml:"parent_key_provider,omitempty"` // Where to get parent keys for unwrapping
}

// TopologySegment defines an agent's portion of the hierarchy
type TopologySegment struct {
	Name           string                `yaml:"name"`         // Agent name (must match cert CN)
	Segment        HierarchySegment      `yaml:"segment"`      // Keys this agent manages
	KeyBindings    map[string]KeyBinding `yaml:"key_bindings"` // All dependencies per key kind (key = kind name)
	SelectorLabels SelectorLabels        `yaml:"selector_labels,omitempty"`
	SubAgentIDs    []KryptonID           `yaml:"-"` // Derived by DeriveSubAgentIDs(), not from config
}

// Topology defines the deployment layout
type Topology struct {
	Segments []TopologySegment `yaml:"segments"` // List of agent segments (0 to N agents)
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
	if kb.Vault.Name == "" && kb.Vault.Type == "" {
		return ErrVaultConfigMissing
	}
	if kb.Vault.Name == "" {
		return ErrVaultNameEmpty
	}
	if kb.Vault.Type == "" {
		return ErrVaultTypeEmpty
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

// MarshalYAML implements [yaml.Marshaler].
// Required because Config is tagged yaml:"-" to prevent interface decode issues.
func (v VaultSpec) MarshalYAML() (any, error) {
	type alias VaultSpec
	return struct {
		alias `yaml:",inline"`

		Config VaultConfig `yaml:"config"`
	}{
		alias:  alias(v),
		Config: v.Config,
	}, nil
}

// UnmarshalYAML implements [yaml.Unmarshaler].
func (v *VaultSpec) UnmarshalYAML(node *yaml.Node) error {
	type alias VaultSpec
	var raw struct {
		alias `yaml:",inline"`

		Config yaml.Node `yaml:"config"`
	}
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode vault spec: %w", err)
	}

	var config VaultConfig
	switch raw.Type {
	case VaultTypeOpenBAO:
		config = &OpenBAOConfig{}
	case VaultTypeInMemory:
		config = &InMemoryConfig{}
	default:
		return fmt.Errorf("unsupported vault type '%s': %w", raw.Type, ErrVaultConfigInvalid)
	}

	if err := raw.Config.Decode(config); err != nil {
		return fmt.Errorf("failed to decode vault config: %w", err)
	}

	*v = VaultSpec(raw.alias)
	v.Config = config
	return nil
}

// DeriveSubAgentIDs populates each segment's SubAgentID list by scanning all key bindings
// to find which segments reference it as their ParentKeyProvider.
func (t *Topology) DeriveSubAgentIDs(trustDomain string) {
	agentToSubAgents := make(map[string][]KryptonID)

	for _, seg := range t.Segments {
		for _, binding := range seg.KeyBindings {
			if binding.ParentKeyProvider != nil {
				name := binding.ParentKeyProvider.AgentName
				if agentToSubAgents[name] == nil {
					agentToSubAgents[name] = make([]KryptonID, 0)
				}
				agentToSubAgents[name] = append(agentToSubAgents[name], AgentID(trustDomain, seg.Name))
			}
		}
	}

	for i := range t.Segments {
		t.Segments[i].SubAgentIDs = agentToSubAgents[t.Segments[i].Name]
	}
}
