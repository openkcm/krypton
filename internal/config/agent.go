package config

import "github.com/openkcm/krypton/internal/spec"

type (
	Role            string
	KeepAliveConfig int
)

const (
	AgentRole Role = "agent"
	RootRole  Role = "root"

	// defaultKeepAlive is the default keep-alive interval (in seconds) assigned to agents.
	defaultKeepAlive KeepAliveConfig = 30
)

// AgentConfig is the configuration returned to an agent during registration.
type AgentConfig struct {
	Name            string                     `yaml:"name"`
	KeyBindings     map[string]spec.KeyBinding `yaml:"key_bindings"`
	IdentityConfigs IdentityConfigs            `yaml:"identity"`
	Segment         spec.HierarchySegment      `yaml:"segment"`
	SelectorLabels  spec.SelectorLabels        `yaml:"selector_labels"`
	Role            Role                       `yaml:"role"`
	Hierarchy       spec.KeyHierarchy          `yaml:"hierarchy"`
	KeepAlive       KeepAliveConfig            `yaml:"keep_alive"`
}

// NewAgentConfig creates a new AgentConfig based on the provided KeyHierarchy and TopologySegment.
func NewAgentConfig(h spec.KeyHierarchy, seg spec.TopologySegment, identities IdentityConfigs) AgentConfig {
	return AgentConfig{
		Name:            seg.Name,
		IdentityConfigs: identities,
		KeyBindings:     seg.KeyBindings,
		Segment:         seg.Segment,
		SelectorLabels:  seg.SelectorLabels,
		Role:            AgentRole,
		Hierarchy:       h,
		KeepAlive:       defaultKeepAlive,
	}
}
