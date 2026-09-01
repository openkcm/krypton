package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/internal/spec"
)

var (
	ErrConfigNameEmpty        = errors.New("config name cannot be empty")
	ErrRoleInvalid            = errors.New("invalid config role")
	ErrConfigAddressEmpty     = errors.New("address URL cannot be empty")
	ErrConfigKeyBindingsEmpty = errors.New("key bindings cannot be empty")
)

// AddressType identifies the transport protocol for inter-service communication.
type AddressType string

const (
	// AddressTypeHTTP represents HTTP/HTTPS transport.
	AddressTypeHTTP AddressType = "http"
	// AddressTypeGRPC represents gRPC transport.
	AddressTypeGRPC AddressType = "grpc"
)

// Address represents a network address for inter-service communication.
type Address struct {
	Type AddressType `yaml:"type"`
	URL  string      `yaml:"url"`
}

// KryptonRoot holds the configuration for reaching the root instance.
type KryptonRoot struct {
	Address Address `yaml:"address"`
}

// RootConfig is the complete configuration for the root instance combining hierarchy and topology.
type RootConfig struct {
	Name           string                     `yaml:"name"`
	Role           spec.AgentRole             `yaml:"role"`
	Auth           *RootAuthConfig            `yaml:"auth,omitempty"`
	Segment        spec.HierarchySegment      `yaml:"segment"`
	SelectorLabels spec.SelectorLabels        `yaml:"selector_labels,omitempty"`
	KeyBindings    map[string]spec.KeyBinding `yaml:"key_bindings"`
	Hierarchy      spec.KeyHierarchy          `yaml:"hierarchy"`
	Topology       spec.Topology              `yaml:"topology"`
	Reconciler     ReconcilerConfig           `yaml:"reconciler"`
	KMIP           *kmip.Config               `yaml:"kmip,omitempty"`
}

// AgentBootstrapConfig is the minimal configuration that agents load from file on startup. It contains just enough information to connect to root.
type AgentBootstrapConfig struct {
	Name        string           `yaml:"name"`
	Role        spec.AgentRole   `yaml:"role"`
	Auth        *AgentAuthConfig `yaml:"auth,omitempty"`
	KryptonRoot KryptonRoot      `yaml:"krypton_root"`
}

// Validate checks the RootConfig for structural correctness.
func (cfg *RootConfig) Validate() error {
	if cfg.Name == "" {
		return ErrConfigNameEmpty
	}
	if err := cfg.Reconciler.Validate(); err != nil {
		return fmt.Errorf("reconciler: %w", err)
	}
	if cfg.Role != spec.RootRole {
		return fmt.Errorf("%w: must be %q", ErrRoleInvalid, spec.RootRole)
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

// Validate checks the AgentBootstrapConfig for structural correctness.
func (cfg *AgentBootstrapConfig) Validate() error {
	if cfg.Name == "" {
		return ErrConfigNameEmpty
	}
	if cfg.Role != spec.DefaultRole {
		return fmt.Errorf("%w: must be %q", ErrRoleInvalid, spec.DefaultRole)
	}
	if cfg.KryptonRoot.Address.URL == "" {
		return ErrConfigAddressEmpty
	}
	if cfg.Auth != nil {
		if err := cfg.Auth.Validate(); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	return nil
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

// LoadAgentBootstrapConfig reads a YAML file, parses it into an AgentBootstrapConfig, and validates it.
func LoadAgentBootstrapConfig(path string) (*AgentBootstrapConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var cfg AgentBootstrapConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}
