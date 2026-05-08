package authz

import (
	"fmt"

	"github.com/openkcm/krypton/internal/authn"
)

// Topology generates builtin policies from the agent topology.
// These encode the topology-based authorization rules:
//   - Root can do anything within its trust domain
//   - Any node can call root
//   - Each sub-agent can call its parent
//   - Implicit deny covers all other cases (no policy needed)
func Topology(self authn.Identity, subAgents []authn.Identity) ([]Policy, error) {
	if len(self.Segments) == 0 || self.Segments[0].Kind != authn.KindNode {
		return nil, fmt.Errorf("selfID must be a node identity: %s", self.URI())
	}

	td := self.TrustDomain

	policies := []Policy{
		{
			ID:   "topology:root-unrestricted",
			Name: "root-unrestricted",
			Statements: []Statement{
				{
					Effect: EffectAllow,
					Principals: []IdentityPattern{
						{
							TrustDomain: td,
							Segments: []PatternSegment{
								{Kind: authn.KindNode, Name: "root"},
							},
						},
					},
					Actions: []ActionPattern{"*"},
					Resources: []IdentityPattern{
						{
							TrustDomain: td,
							Segments: []PatternSegment{
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
					Principals: []IdentityPattern{
						{
							TrustDomain: td,
							Segments: []PatternSegment{
								{Kind: authn.KindNode, Name: "*"},
							},
						},
					},
					Actions: []ActionPattern{"*"},
					Resources: []IdentityPattern{
						{
							TrustDomain: td,
							Segments: []PatternSegment{
								{Kind: authn.KindNode, Name: "root"},
							},
						},
					},
				},
			},
		},
	}

	for _, sub := range subAgents {
		if len(sub.Segments) == 0 || sub.Segments[0].Kind != authn.KindNode {
			return nil, fmt.Errorf("sub-agent must be a node identity: %s", sub.URI())
		}

		policies = append(policies, Policy{
			ID:   fmt.Sprintf("topology:sub-agent-%s", sub.Segments[0].Name),
			Name: fmt.Sprintf("sub-agent-%s-calls-parent", sub.Segments[0].Name),
			Statements: []Statement{
				{
					Effect: EffectAllow,
					Principals: []IdentityPattern{
						{
							TrustDomain: sub.TrustDomain,
							Segments:    toPatternSegments(sub.Segments),
						},
					},
					Actions: []ActionPattern{"*"},
					Resources: []IdentityPattern{
						{
							TrustDomain: self.TrustDomain,
							Segments:    toPatternSegments(self.Segments),
						},
					},
				},
			},
		})
	}

	return policies, nil
}

// toPatternSegments converts concrete authn.Segments to PatternSegments (exact match).
func toPatternSegments(segs []authn.Segment) []PatternSegment {
	ps := make([]PatternSegment, len(segs))
	for i, s := range segs {
		ps[i] = PatternSegment{Kind: s.Kind, Name: s.Name}
	}
	return ps
}
