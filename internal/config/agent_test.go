package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/spec"
)

func TestNewAgentConfig(t *testing.T) {
	// given
	topologySegment := spec.TopologySegment{
		Name:           "segment1",
		SelectorLabels: map[string]string{"region": "us-west"},
		Segment: spec.HierarchySegment{
			StartKind: "K1",
			EndKind:   "K2",
		},
		KeyBindings: map[string]spec.KeyBinding{
			"binding1": {
				CryptorSpec:       validCryptor(),
				ParentKeyProvider: &spec.ParentKeyProviderRef{},
			},
		},
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
	expIdentityConfigs := config.IdentityConfigs{
		{
			Name: "root",
			URI:  "root",
		},
	}

	expConfig := config.AgentConfig{
		Name:            "segment1",
		IdentityConfigs: expIdentityConfigs,
		KeyBindings:     topologySegment.KeyBindings,
		Segment:         topologySegment.Segment,
		SelectorLabels:  topologySegment.SelectorLabels,
		Role:            config.AgentRole,
		Hierarchy:       expHierarchy,
		KeepAlive:       30,
	}

	// when
	actConfig := config.NewAgentConfig(expHierarchy, topologySegment, expIdentityConfigs)

	// then
	assert.Equal(t, expConfig, actConfig)
}

func validCryptor() *cryptorprovider.Spec {
	return &cryptorprovider.Spec{
		Name:   "test-crypto",
		Type:   aes256gcm.TypeAES256GCM,
		Config: &aes256gcm.Config{},
	}
}
