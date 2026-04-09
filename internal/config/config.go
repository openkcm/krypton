package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

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
	Name        string                     `yaml:"name"`
	Role        spec.AgentRole             `yaml:"role"`
	Segment     spec.HierarchySegment      `yaml:"segment"`
	Labels      spec.Labels                `yaml:"labels,omitempty"`
	KeyBindings map[string]spec.KeyBinding `yaml:"key_bindings"`
	Hierarchy   spec.KeyHierarchy          `yaml:"hierarchy"`
	Topology    spec.Topology              `yaml:"topology"`
}

// AgentBootstrapConfig is the minimal configuration that agents load from file on startup. It contains just enough information to connect to root.
type AgentBootstrapConfig struct {
	Name        string         `yaml:"name"`
	Role        spec.AgentRole `yaml:"role"`
	KryptonRoot KryptonRoot    `yaml:"krypton_root"`
}

// Validate checks the RootConfig for structural correctness.
func (cfg *RootConfig) Validate() error {
	if cfg.Name == "" {
		return ErrConfigNameEmpty
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
