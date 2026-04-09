package models_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/models"
)

func TestNewAgentConfig(t *testing.T) {
	// given
	topologySegment := models.TopologySegment{
		Name:   "segment1",
		Labels: map[string]string{"region": "us-west"},
		Segment: models.HierarchySegment{
			StartKind: "K2",
			EndKind:   "K2",
		},
		KeyBindings: map[string]models.KeyBinding{
			"binding1": {
				Vault:             models.VaultSpec{},
				ParentKeyProvider: &models.ParentKeyProviderRef{},
				Labels:            models.Labels{},
			},
		},
	}
	expHierarchy := models.KeyHierarchy{
		Name: "some-hierarchy",
		KeySpecs: []models.KeySpec{
			{
				Kind:      "K1",
				Role:      models.KeyRoleRoot,
				Algorithm: "",
			},
			{
				Kind:      "K2",
				Role:      models.KeyRoleDek,
				Algorithm: "",
			},
		},
	}

	expConfig := models.AgentConfig{
		Name:        "segment1",
		KeyBindings: topologySegment.KeyBindings,
		Segment:     topologySegment.Segment,
		Labels:      topologySegment.Labels,
		Role:        models.DefaultRole,
		Hierarchy:   expHierarchy,
		KeepAlive:   30,
	}

	// when
	actConfig := models.NewAgentConfig(expHierarchy, topologySegment)

	// then
	assert.Equal(t, expConfig, actConfig)
}
