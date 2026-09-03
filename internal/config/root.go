package config

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/internal/spec"
)

var (
	ErrConfigNameEmpty        = errors.New("config name cannot be empty")
	ErrRoleInvalid            = errors.New("invalid config role")
	ErrConfigKeyBindingsEmpty = errors.New("key bindings cannot be empty")
	ErrAuthConfigMissing      = errors.New("auth config is missing")
	ErrAgentNotAllowed        = errors.New("agent is not allowed to connect to root")
	ErrIdentityConfigsMissing = errors.New("identity configs missing for topology members")
)

// RootConfig is the complete configuration for the root instance combining hierarchy and topology.
type RootConfig struct {
	Name           string                     `yaml:"name"`
	Role           Role                       `yaml:"role"`
	Auth           *RootAuthConfig            `yaml:"auth,omitempty"`
	Segment        spec.HierarchySegment      `yaml:"segment"`
	SelectorLabels spec.SelectorLabels        `yaml:"selector_labels,omitempty"`
	KeyBindings    map[string]spec.KeyBinding `yaml:"key_bindings"`
	Hierarchy      spec.KeyHierarchy          `yaml:"hierarchy"`
	Topology       spec.Topology              `yaml:"topology"`
	Reconciler     ReconcilerConfig           `yaml:"reconciler"`
	KMIP           *kmip.Config               `yaml:"kmip,omitempty"`
}

// Validate checks the RootConfig for structural correctness.
func (cfg *RootConfig) Validate() error {
	if cfg.Name == "" {
		return ErrConfigNameEmpty
	}
	if err := cfg.Reconciler.Validate(); err != nil {
		return fmt.Errorf("reconciler: %w", err)
	}
	if cfg.Role != RootRole {
		return fmt.Errorf("%w: must be %q", ErrRoleInvalid, RootRole)
	}
	if err := cfg.Hierarchy.Validate(); err != nil {
		return fmt.Errorf("hierarchy: %w", err)
	}
	if err := cfg.Topology.Validate(); err != nil {
		return fmt.Errorf("topology: %w", err)
	}
	if err := cfg.Segment.Validate(); err != nil {
		return fmt.Errorf("segment: %w", err)
	}
	if len(cfg.KeyBindings) == 0 {
		return ErrConfigKeyBindingsEmpty
	}

	if err := spec.ValidateRootSegment(cfg.Hierarchy, cfg.Segment, cfg.KeyBindings); err != nil {
		return fmt.Errorf("root segment: %w", err)
	}
	if err := spec.ValidateTopologyAgainstHierarchy(cfg.Hierarchy, cfg.Topology, cfg.Segment, cfg.KeyBindings); err != nil {
		return fmt.Errorf("topology: %w", err)
	}
	if cfg.KMIP != nil {
		if err := cfg.KMIP.Validate(); err != nil {
			return fmt.Errorf("kmip: %w", err)
		}
	}
	if cfg.Auth != nil {
		if err := cfg.Auth.Validate(); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
		if err := cfg.Auth.IdentityConfigs.ValidateAuthIdentities(cfg); err != nil {
			return fmt.Errorf("auth identities: %w", err)
		}
	}

	return nil
}

// AgentIdentities returns the identity configs required by the named agent:
// the identities of its topology children plus the root's own identity. It
// returns ErrAuthConfigMissing if the root has no auth config, ErrAgentNotAllowed
// if the agent is not present in the configured identities, and
// ErrIdentityConfigsMissing if any required child/root identity has no configured entry.
func (cfg *RootConfig) AgentIdentities(agentName string) (IdentityConfigs, error) {
	if cfg.Auth == nil {
		return nil, fmt.Errorf("%w: no auth config found in root config", ErrAuthConfigMissing)
	}

	cns, ok := cfg.Topology.ChildrenNames(agentName)
	if !ok {
		cns = make(map[string]struct{}, 1)
	}
	cns[cfg.Name] = struct{}{}

	res := make(IdentityConfigs, 0, len(cns))

	isAgentAllowed := false
	for _, id := range cfg.Auth.IdentityConfigs {
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
