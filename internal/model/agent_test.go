package model_test

import (
	"testing"

	"github.com/openkcm/krypton/internal/model"
	"github.com/openkcm/krypton/internal/models"
	"github.com/stretchr/testify/assert"
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
	expHierarchy := model.KeyHierarchy{
		Name: "some-hierarchy",
		KeySpecs: []model.KeySpec{
			{
				Kind:      "K1",
				Role:      model.KeyRoleRoot,
				Algorithm: "",
			},
			{
				Kind:      "K2",
				Role:      model.KeyRoleDek,
				Algorithm: "",
			},
		},
	}

	expConfig := model.AgentConfig{
		Name:        "segment1",
		KeyBindings: topologySegment.KeyBindings,
		Segment:     topologySegment.Segment,
		Labels:      topologySegment.Labels,
		Role:        model.DefaultRole,
		Hierarchy:   expHierarchy,
		KeepAlive:   30,
	}

	// when
	actConfig := model.NewAgentConfig(expHierarchy, topologySegment)

	// then
	assert.Equal(t, expConfig, actConfig)
}
