package authz_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/authz"
	"github.com/openkcm/krypton/internal/spec"
)

const testTrustDomain = "acme-corp"

func TestNew(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		selfID      spec.KryptonID
		subAgentIDs []spec.KryptonID
	}{
		{
			name:        "valid with sub-agents",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
		},
		{
			name:        "valid with nil sub-agents",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: nil,
		},
		{
			name:        "valid with empty sub-agents",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{},
		},
		{
			name:   "valid root",
			selfID: spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{
				spec.AgentID(testTrustDomain, "agent-aws"),
				spec.AgentID(testTrustDomain, "agent-gcp"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// when
			authZ := authz.New(tt.selfID, tt.subAgentIDs)

			// then
			assert.NotNil(t, authZ)
		})
	}
}

func TestAuthorize(t *testing.T) {
	t.Parallel()

	// Hierarchy: K0 -> K1 -> K2 -> K3 -> K4
	// Root manages K0->K1, has sub-agents: [agent-aws, agent-gcp]
	// agent-aws manages K2->K3, has sub-agents: [agent-leaf]
	// agent-gcp manages K2->K3, has sub-agents: []
	// agent-leaf manages K4, has sub-agents: []

	tests := []struct {
		name        string
		selfID      spec.KryptonID
		subAgentIDs []spec.KryptonID
		ctx         authz.Context
		expErr      error
	}{
		// Rule 0: Trust domains must match
		{
			name:        "trust domain mismatch is denied",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			ctx: authz.Context{
				CallerID: spec.RootID("other-domain"),
				TargetID: spec.AgentID(testTrustDomain, "agent-aws"),
			},
			expErr: authz.ErrTrustDomainMismatch,
		},

		// Rule 1: Root can call anyone
		{
			name:        "root can call agent-aws",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			ctx: authz.Context{
				CallerID: spec.RootID(testTrustDomain),
				TargetID: spec.AgentID(testTrustDomain, "agent-aws"),
			},
		},
		{
			name:        "root can call agent-leaf",
			selfID:      spec.AgentID(testTrustDomain, "agent-leaf"),
			subAgentIDs: []spec.KryptonID{},
			ctx: authz.Context{
				CallerID: spec.RootID(testTrustDomain),
				TargetID: spec.AgentID(testTrustDomain, "agent-leaf"),
			},
		},
		{
			name:   "root can call root",
			selfID: spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{
				spec.AgentID(testTrustDomain, "agent-aws"),
				spec.AgentID(testTrustDomain, "agent-gcp"),
			},
			ctx: authz.Context{
				CallerID: spec.RootID(testTrustDomain),
				TargetID: spec.RootID(testTrustDomain),
			},
		},

		// Rule 2: Anyone can call root
		{
			name:   "agent-aws can call root",
			selfID: spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{
				spec.AgentID(testTrustDomain, "agent-aws"),
				spec.AgentID(testTrustDomain, "agent-gcp"),
			},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-aws"),
				TargetID: spec.RootID(testTrustDomain),
			},
		},
		{
			name:   "agent-leaf can call root",
			selfID: spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{
				spec.AgentID(testTrustDomain, "agent-aws"),
				spec.AgentID(testTrustDomain, "agent-gcp"),
			},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-leaf"),
				TargetID: spec.RootID(testTrustDomain),
			},
		},
		{
			name:   "unknown agent can call root",
			selfID: spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{
				spec.AgentID(testTrustDomain, "agent-aws"),
				spec.AgentID(testTrustDomain, "agent-gcp"),
			},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "unknown-agent"),
				TargetID: spec.RootID(testTrustDomain),
			},
		},

		// Rule 3: Sub-agent can call parent
		{
			name:        "agent-leaf can call agent-aws (sub-agent calls parent)",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-leaf"),
				TargetID: spec.AgentID(testTrustDomain, "agent-aws"),
			},
		},

		// Rule 4: Deny other combinations
		{
			name:        "agent-aws cannot call agent-leaf (parent cannot call sub-agent)",
			selfID:      spec.AgentID(testTrustDomain, "agent-leaf"),
			subAgentIDs: []spec.KryptonID{},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-aws"),
				TargetID: spec.AgentID(testTrustDomain, "agent-leaf"),
			},
			expErr: authz.ErrUnauthorized,
		},
		{
			name:        "agent-aws cannot call agent-gcp (siblings cannot call each other)",
			selfID:      spec.AgentID(testTrustDomain, "agent-gcp"),
			subAgentIDs: []spec.KryptonID{},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-aws"),
				TargetID: spec.AgentID(testTrustDomain, "agent-gcp"),
			},
			expErr: authz.ErrUnauthorized,
		},
		{
			name:        "agent-gcp cannot call agent-aws (siblings cannot call each other)",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-gcp"),
				TargetID: spec.AgentID(testTrustDomain, "agent-aws"),
			},
			expErr: authz.ErrUnauthorized,
		},
		{
			name:        "agent-leaf cannot call agent-gcp (no relationship)",
			selfID:      spec.AgentID(testTrustDomain, "agent-gcp"),
			subAgentIDs: []spec.KryptonID{},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-leaf"),
				TargetID: spec.AgentID(testTrustDomain, "agent-gcp"),
			},
			expErr: authz.ErrUnauthorized,
		},

		// Edge cases
		{
			name:        "nil subAgentIDs - agent calling non-root",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: nil,
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-leaf"),
				TargetID: spec.AgentID(testTrustDomain, "agent-aws"),
			},
			expErr: authz.ErrUnauthorized,
		},
		{
			name:        "empty subAgentIDs - agent calling non-root",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{},
			ctx: authz.Context{
				CallerID: spec.AgentID(testTrustDomain, "agent-leaf"),
				TargetID: spec.AgentID(testTrustDomain, "agent-aws"),
			},
			expErr: authz.ErrUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			authZ := authz.New(tt.selfID, tt.subAgentIDs)

			// when
			err := authZ.Authorize(tt.ctx)

			// then
			if tt.expErr != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}
