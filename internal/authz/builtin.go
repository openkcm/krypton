package authz

import (
	"fmt"

	"github.com/openkcm/krypton/internal/identity"
)

// KindNode is the segment kind for agent nodes in a topology.
const KindNode = "node"

// NameRoot is the name of the root node in a topology.
const NameRoot = "root"

// Topology generates builtin policies from the agent topology.
// These encode the topology-based authorization rules:
//   - Root can do anything within its trust domain
//   - Any node can call root
//   - Each sub-agent can call its parent (non-root only)
//   - Implicit deny covers all other cases (no policy needed)
func Topology(self identity.Identity, subAgents []identity.Identity) ([]Policy, error) {
	if len(self.Segments) == 0 || self.Segments[0].Kind != KindNode {
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
							Segments: []identity.SegmentSelector{
								{Kind: KindNode, Name: NameRoot},
							},
						},
					},
					Actions: []ActionSelector{"*"},
					Resources: []identity.Selector{
						{
							Domain: self.Domain,
							Segments: []identity.SegmentSelector{
								{Kind: "**"},
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
							Segments: []identity.SegmentSelector{
								{Kind: KindNode, Name: "*"},
							},
						},
					},
					Actions: []ActionSelector{"*"},
					Resources: []identity.Selector{
						{
							Domain: self.Domain,
							Segments: []identity.SegmentSelector{
								{Kind: KindNode, Name: NameRoot},
							},
						},
					},
				},
			},
		},
	}

	// Root doesn't need sub-agent policies — anyone-calls-root already covers it.
	if self.Segments[0].Name == NameRoot {
		return policies, nil
	}

	// Non-root: each sub-agent can call this node (its parent).
	for _, sub := range subAgents {
		if len(sub.Segments) == 0 || sub.Segments[0].Kind != KindNode {
			return nil, fmt.Errorf("sub-agent must be a node identity: %s", sub.URI())
		}

		policies = append(policies, Policy{
			ID:   "topology:sub-agent-" + sub.Segments[0].Name,
			Name: fmt.Sprintf("sub-agent-%s-calls-parent", sub.Segments[0].Name),
			Statements: []Statement{
				{
					Effect: EffectAllow,
					Principals: []identity.Selector{
						{
							Domain:   sub.Domain,
							Segments: toSegmentSelectors(sub.Segments),
						},
					},
					Actions: []ActionSelector{"*"},
					Resources: []identity.Selector{
						{
							Domain:   self.Domain,
							Segments: toSegmentSelectors(self.Segments),
						},
					},
				},
			},
		})
	}

	return policies, nil
}

// toSegmentSelectors converts concrete Segments to SegmentSelectors (exact match).
func toSegmentSelectors(segs []identity.Segment) []identity.SegmentSelector {
	ss := make([]identity.SegmentSelector, len(segs))
	for i, s := range segs {
		ss[i] = identity.SegmentSelector(s)
	}
	return ss
}
