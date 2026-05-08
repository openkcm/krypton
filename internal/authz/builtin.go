package authz

import (
	"fmt"

	"github.com/openkcm/krypton/internal/identity"
)

// TypeNode is the field type for agent nodes in a topology.
const TypeNode = "node"

// NameRoot is the name of the root node in a topology.
const NameRoot = "root"

// Topology generates builtin policies from the agent topology.
// These encode the topology-based authorization rules:
//   - Root can do anything within its trust domain
//   - Any node can call root
//   - Each sub-agent can call its parent (non-root only)
//   - Implicit deny covers all other cases (no policy needed)
func Topology(self identity.Identity, subAgents []identity.Identity) ([]Policy, error) {
	if len(self.Fields) == 0 || self.Fields[0].Type != TypeNode {
		return nil, fmt.Errorf("self must be a node identity: %s", self.URI())
	}

	// Base policies that every node needs: root is unrestricted, any node can call root.
	policies := []Policy{
		{
			ID:   "topology:root-unrestricted",
			Name: "root-unrestricted",
			Statements: []Statement{
				{
					Effect: EffectAllow,
					Principals: []identity.Selector{
						{
							Domain: self.Domain,
							Fields: []identity.FieldSelector{
								{Type: TypeNode, Name: NameRoot},
							},
						},
					},
					Actions: []ActionSelector{"*"},
					Resources: []identity.Selector{
						{
							Domain: self.Domain,
							Fields: []identity.FieldSelector{
								{Type: "**"},
							},
						},
					},
				},
			},
		},
		{
			ID:   "topology:anyone-calls-root",
			Name: "anyone-calls-root",
			Statements: []Statement{
				{
					Effect: EffectAllow,
					Principals: []identity.Selector{
						{
							Domain: self.Domain,
							Fields: []identity.FieldSelector{
								{Type: TypeNode, Name: "*"},
							},
						},
					},
					Actions: []ActionSelector{"*"},
					Resources: []identity.Selector{
						{
							Domain: self.Domain,
							Fields: []identity.FieldSelector{
								{Type: TypeNode, Name: NameRoot},
							},
						},
					},
				},
			},
		},
	}

	// Root doesn't need sub-agent policies — anyone-calls-root already covers it.
	if self.Fields[0].Name == NameRoot {
		return policies, nil
	}

	// Non-root: each sub-agent can call this node (its parent).
	for _, sub := range subAgents {
		if len(sub.Fields) == 0 || sub.Fields[0].Type != TypeNode {
			return nil, fmt.Errorf("sub-agent must be a node identity: %s", sub.URI())
		}

		policies = append(policies, Policy{
			ID:   "topology:sub-agent-" + sub.Fields[0].Name,
			Name: fmt.Sprintf("sub-agent-%s-calls-parent", sub.Fields[0].Name),
			Statements: []Statement{
				{
					Effect: EffectAllow,
					Principals: []identity.Selector{
						{
							Domain: sub.Domain,
							Fields: toFieldSelectors(sub.Fields),
						},
					},
					Actions: []ActionSelector{"*"},
					Resources: []identity.Selector{
						{
							Domain: self.Domain,
							Fields: toFieldSelectors(self.Fields),
						},
					},
				},
			},
		})
	}

	return policies, nil
}

// toFieldSelectors converts concrete Fields to FieldSelectors (exact match).
func toFieldSelectors(fields []identity.Field) []identity.FieldSelector {
	fs := make([]identity.FieldSelector, len(fields))
	for i, f := range fields {
		fs[i] = identity.FieldSelector(f)
	}
	return fs
}
