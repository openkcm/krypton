package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/spec"
)

type (
	Role            string
	KeepAliveConfig int
)

const (
	// AgentRole represents the role of an agent in the system.
	AgentRole Role = "agent"
	// RootRole represents the role of the root instance in the system.
	RootRole Role = "root"

	// defaultKeepAlive is the default keep-alive interval (in seconds) assigned to agents.
	defaultKeepAlive KeepAliveConfig = 30
)

// KryptonRoot holds the configuration for reaching the root instance.
type KryptonRoot struct {
	Address Address `yaml:"address"`
}

// AgentConfig is the configuration returned to an agent during registration.
type AgentConfig struct {
	Name            string                     `yaml:"name"`
	KeyBindings     map[string]spec.KeyBinding `yaml:"key_bindings"`
	Connections     ConnectionConfigs          `yaml:"connections"`
	IdentityConfigs IdentityConfigs            `yaml:"identity"`
	Segment         spec.HierarchySegment      `yaml:"segment"`
	SelectorLabels  spec.SelectorLabels        `yaml:"selector_labels"`
	Role            Role                       `yaml:"role"`
	Hierarchy       spec.KeyHierarchy          `yaml:"hierarchy"`
	KeepAlive       KeepAliveConfig            `yaml:"keep_alive"`
}

// AgentBootstrapConfig is the minimal configuration that agents load from file on startup. It contains just enough information to connect to root.
type AgentBootstrapConfig struct {
	Name        string           `yaml:"name"`
	Role        Role             `yaml:"role"`
	Auth        *AgentAuthConfig `yaml:"auth,omitempty"`
	KryptonRoot KryptonRoot      `yaml:"krypton_root"`
}

var ErrConfigAddressEmpty = errors.New("address URL cannot be empty")
var ErrAddressTypeInvalid = errors.New("address type must be 'grpc'")

// NewAgentConfig creates a new AgentConfig based on the provided KeyHierarchy and TopologySegment.
func NewAgentConfig(h spec.KeyHierarchy, seg spec.TopologySegment, identities IdentityConfigs, connections ConnectionConfigs) AgentConfig {
	return AgentConfig{
		Name:            seg.Name,
		IdentityConfigs: identities,
		Connections:     connections,
		KeyBindings:     seg.KeyBindings,
		Segment:         seg.Segment,
		SelectorLabels:  seg.SelectorLabels,
		Role:            AgentRole,
		Hierarchy:       h,
		KeepAlive:       defaultKeepAlive,
	}
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

// Validate checks the AgentBootstrapConfig for structural correctness.
func (cfg *AgentBootstrapConfig) Validate() error {
	if cfg.Name == "" {
		return ErrConfigNameEmpty
	}
	if cfg.Role != AgentRole {
		return fmt.Errorf("%w: must be %q", ErrRoleInvalid, AgentRole)
	}
	if err := cfg.KryptonRoot.Address.Validate(); err != nil {
		return fmt.Errorf("krypton_root.address: %w", err)
	}
	if cfg.Auth != nil {
		if err := cfg.Auth.Validate(); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	return nil
}

// UnmarshalAgentConfig takes a byte slice containing YAML data and unmarshals it into an AgentConfig struct.
func UnmarshalAgentConfig(b []byte) (*AgentConfig, error) {
	var cfg AgentConfig
	err := yaml.Unmarshal(b, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
