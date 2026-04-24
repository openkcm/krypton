package spec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
)

func TestNewAgentConfig(t *testing.T) {
	// given
	topologySegment := spec.TopologySegment{
		Name:           "segment1",
		SelectorLabels: map[string]string{"region": "us-west"},
		Segment: spec.HierarchySegment{
			StartKind: "K2",
			EndKind:   "K2",
		},
		KeyBindings: map[string]spec.KeyBinding{
			"binding1": {
				Vault:             spec.VaultSpec{},
				ParentKeyProvider: &spec.ParentKeyProviderRef{},
			},
		},
		SubAgents: []string{"agent-leaf"},
	}
	expHierarchy := spec.KeyHierarchy{
		Name: "some-hierarchy",
		KeySpecs: []spec.KeySpec{
			{
				Kind:      "K1",
				Role:      spec.KeyRoleRoot,
				Algorithm: "",
			},
			{
				Kind:      "K2",
				Role:      spec.KeyRoleDek,
				Algorithm: "",
			},
		},
	}

	expConfig := spec.AgentConfig{
		Name:           "segment1",
		KeyBindings:    topologySegment.KeyBindings,
		Segment:        topologySegment.Segment,
		SelectorLabels: topologySegment.SelectorLabels,
		Role:           spec.DefaultRole,
		Hierarchy:      expHierarchy,
		KeepAlive:      30,
		SubAgents:      []string{"agent-leaf"},
	}

	// when
	actConfig := spec.NewAgentConfig(expHierarchy, topologySegment)

	// then
	assert.Equal(t, expConfig, actConfig)
}
