package model

import "github.com/openkcm/krypton/internal/models"

type (
	AgentRole       string
	KeepAliveConfig int
)

var DefaultRole AgentRole = "agent"

type AgentConfig struct {
	Name        string                       `json:"name"`
	KeyBindings map[string]models.KeyBinding `json:"key_bindings"`
	Segment     models.HierarchySegment      `json:"segment"`
	Labels      models.Labels                `json:"labels"`
	Role        AgentRole                    `json:"role"`
	Hierarchy   KeyHierarchy                 `json:"hierarchy"`
	KeepAlive   KeepAliveConfig              `json:"keep_alive"`
}

func NewAgentConfig(KeyHierarchy KeyHierarchy, seg models.TopologySegment) AgentConfig {
	return AgentConfig{
		Name:        seg.Name,
		KeyBindings: seg.KeyBindings,
		Segment:     seg.Segment,
		Labels:      seg.Labels,
		Role:        DefaultRole,
		Hierarchy:   KeyHierarchy,
		KeepAlive:   30,
	}
}
