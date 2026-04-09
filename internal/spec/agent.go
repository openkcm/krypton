package spec

type (
	AgentRole       string
	KeepAliveConfig int
)

var (
	// DefaultRole is the default role assigned to agents if not specified otherwise.
	DefaultRole AgentRole = "agent"
	RootRole    AgentRole = "root"
)

// AgentConfig represents the configuration for an agent, including its name, key bindings, segment, labels, role, hierarchy, and keep-alive settings.
type AgentConfig struct {
	Name        string                `json:"name"`
	KeyBindings map[string]KeyBinding `json:"key_bindings"`
	Segment     HierarchySegment      `json:"segment"`
	Labels      Labels                `json:"labels"`
	Role        AgentRole             `json:"role"`
	Hierarchy   KeyHierarchy          `json:"hierarchy"`
	KeepAlive   KeepAliveConfig       `json:"keep_alive"`
}

// NewAgentConfig creates a new AgentConfig based on the provided KeyHierarchy and TopologySegment.
func NewAgentConfig(h KeyHierarchy, seg TopologySegment) AgentConfig {
	return AgentConfig{
		Name:        seg.Name,
		KeyBindings: seg.KeyBindings,
		Segment:     seg.Segment,
		Labels:      seg.Labels,
		Role:        DefaultRole,
		Hierarchy:   h,
		KeepAlive:   30,
	}
}
