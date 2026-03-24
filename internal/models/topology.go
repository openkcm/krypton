package models

import "errors"

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

// Labels is a key-value map for metadata
type Labels map[string]string

// HierarchySegment represents a contiguous range of key kinds in the hierarchy
type HierarchySegment struct {
	StartKind string // First key kind in segment (e.g., "K2")
	EndKind   string // Last key kind in segment (e.g., "K3") - inclusive
}

// ParentKeyProviderRef specifies which agent provides parent keys for unwrapping
type ParentKeyProviderRef struct {
	AgentName string // Agent name that provides parent keys
}

// Vault holds storage backend configuration
type Vault struct {
	Name   string         // Vault identifier
	Type   string         // Vault type (e.g., "open-bao", "aws-kms", "gcp-kms")
	Params map[string]any // Type-specific configuration
}

// KeyBinding encapsulates all dependencies needed to implement a key kind
type KeyBinding struct {
	Vault             Vault                 // Storage backend configuration
	ParentKeyProvider *ParentKeyProviderRef // Where to get parent keys for unwrapping
	Labels            Labels                // Per-binding labels
}

// TopologySegment defines an agent's portion of the hierarchy
type TopologySegment struct {
	Name        string                // Agent name (must match cert CN)
	Segment     HierarchySegment      // Keys this agent manages
	KeyBindings map[string]KeyBinding // All dependencies per key kind (key = kind name)
	Labels      Labels                // Labels assigned to this agent
}

// Topology defines the deployment layout
type Topology struct {
	Segments []TopologySegment // List of agent segments (0 to N agents)
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
