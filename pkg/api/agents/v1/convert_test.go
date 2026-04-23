package v1_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/spec"
	v1 "github.com/openkcm/krypton/pkg/api/agents/v1"
)

func TestToProto(t *testing.T) {
	// given
	cfg := spec.AgentConfig{
		Name: "agent-aws",
		KeyBindings: map[string]spec.KeyBinding{
			"K1": {
				Vault: spec.VaultSpec{
					Name: "vault1",
					Type: "aws-kms",
					Params: map[string]any{
						"string":    "us-west-2",
						"uuid":      "1234abcd-12ab-34cd-56ef-1234567890ab",
						"booltrue":  true,
						"boolfalse": false,
						"map": map[string]any{
							"nestedKey": "nestedValue",
						},
						"nullValue": nil,
						"float":     3.14,
						// "number":    123,
						// "list":      []string{"a", "b", "c"},
					},
				},
				ParentKeyProvider: &spec.ParentKeyProviderRef{
					AgentName: "agent-aws",
				},
				Labels: spec.Labels{
					"env": "prod",
					"app": "myapp",
				},
			},
		},
		Segment: spec.HierarchySegment{
			StartKind: "K1",
			EndKind:   "K2",
		},
		Labels: spec.Labels{
			"region": "us-west",
			"env":    "prod",
		},
		Role: spec.DefaultRole,
		Hierarchy: spec.KeyHierarchy{
			Name: "some-hierarchy",
			KeySpecs: []spec.KeySpec{
				{
					Kind:      "K1",
					Role:      spec.KeyRoleRoot,
					Algorithm: spec.KeyAlgorithmAES256,
				},
				{
					Kind:      "K2",
					Role:      spec.KeyRoleDek,
					Algorithm: spec.KeyAlgorithmAES256,
				},
			},
		},
		KeepAlive: 20,
	}

	// when
	prot, err := v1.AgentConfigToProto(cfg)
	assert.NoError(t, err)

	newCf := v1.ProtoToAgentConfig(prot)

	// then
	assert.Equal(t, cfg, newCf)
}
