package config

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/spec"
)

var (
	ErrConfigNameEmpty        = errors.New("config name cannot be empty")
	ErrRoleInvalid            = errors.New("invalid config role")
	ErrConfigKeyBindingsEmpty = errors.New("key bindings cannot be empty")
	ErrAuthConfigMissing      = errors.New("auth config is missing")
	ErrAgentNotAllowed        = errors.New("agent is not allowed to connect to root")
	ErrIdentityConfigsMissing = errors.New("identity configs missing for topology members")
	ErrRootKeyMissing         = errors.New("root key config is missing")
)

// RootConfig is the complete configuration for the root instance combining hierarchy and topology.
type RootConfig struct {
	Name           string                     `yaml:"name"`
	Role           Role                       `yaml:"role"`
	Auth           *RootAuthConfig            `yaml:"auth,omitempty"`
	Segment        spec.HierarchySegment      `yaml:"segment"`
	SelectorLabels spec.SelectorLabels        `yaml:"selector_labels,omitempty"`
	RootKey        *spec.RootKeySpec          `yaml:"root_key"`
	KeyBindings    map[string]spec.KeyBinding `yaml:"key_bindings"`
	Hierarchy      spec.KeyHierarchy          `yaml:"hierarchy"`
	Topology       spec.Topology              `yaml:"topology"`
	Connections    ConnectionConfigs          `yaml:"connections"`
	KMIPs          KMIPs                      `yaml:"kmips,omitempty"`
}

// Validate checks the RootConfig for structural correctness.
func (m *RootConfig) Validate() error {
	if m.Name == "" {
		return ErrConfigNameEmpty
	}
	if m.Role != RootRole {
		return fmt.Errorf("%w: must be %q", ErrRoleInvalid, RootRole)
	}
	if err := m.Hierarchy.Validate(); err != nil {
		return fmt.Errorf("hierarchy: %w", err)
	}
	if err := m.Topology.Validate(); err != nil {
		return fmt.Errorf("topology: %w", err)
	}
	if err := m.Segment.Validate(); err != nil {
		return fmt.Errorf("segment: %w", err)
	}
	if len(m.KeyBindings) == 0 {
		return ErrConfigKeyBindingsEmpty
	}
	if m.RootKey == nil {
		return ErrRootKeyMissing
	}
	if err := m.RootKey.Validate(); err != nil {
		return fmt.Errorf("root key: %w", err)
	}
	if err := spec.ValidateRootSegment(m.Hierarchy, m.Segment, m.KeyBindings); err != nil {
		return fmt.Errorf("root segment: %w", err)
	}
	if err := spec.ValidateTopologyAgainstHierarchy(m.Hierarchy, m.Topology, m.Segment, m.KeyBindings); err != nil {
		return fmt.Errorf("topology: %w", err)
	}
	if err := m.KMIPs.Validate(m); err != nil {
		return fmt.Errorf("kmip: %w", err)
	}
	if m.Auth != nil {
		if err := m.Auth.Validate(); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		if err := m.Auth.IdentityConfigs.Validate(m); err != nil {
			return fmt.Errorf("auth identities: %w", err)
		}
	}
	if err := m.Connections.Validate(m); err != nil {
		return fmt.Errorf("connections: %w", err)
	}

	return nil
}

// AgentIdentities returns the identity configs required by the named agent:
// the identities of its topology children plus the root's own identity. It
// returns ErrAuthConfigMissing if the root has no auth config, ErrAgentNotAllowed
// if the agent is not present in the configured identities, and
// ErrIdentityConfigsMissing if any required child/root identity has no configured entry.
func (m *RootConfig) AgentIdentities(agentName string) (IdentityConfigs, error) {
	if m.Auth == nil {
		return nil, fmt.Errorf("%w: no auth config found in root config", ErrAuthConfigMissing)
	}

	cns, ok := m.Topology.ChildrenNames(agentName)
	if !ok {
		cns = make(map[string]struct{}, 1)
	}
	cns[m.Name] = struct{}{}

	res := make(IdentityConfigs, 0, len(cns))

	isAgentAllowed := false
	for _, id := range m.Auth.IdentityConfigs {
		// check if the agent is allowed to connect to root
		if id.Name == agentName {
			isAgentAllowed = true
		}

		if _, ok := cns[id.Name]; ok {
			delete(cns, id.Name)
			res = append(res, id)
		}
	}

	// should not happen as this validated in the mTLS authenticator
	if !isAgentAllowed {
		return nil, fmt.Errorf("%w: %q is not allowed to connect to root", ErrAgentNotAllowed, agentName)
	}

	if len(cns) > 0 {
		return nil, fmt.Errorf("%w: %v", ErrIdentityConfigsMissing, slices.Collect(maps.Keys(cns)))
	}

	return res, nil
}

// LoadRootConfig reads a YAML file, parses it into a RootConfig, and validates it.
func LoadRootConfig(path string) (*RootConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var cfg RootConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
