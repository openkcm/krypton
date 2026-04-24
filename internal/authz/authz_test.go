package authz_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/authz"
)

func TestIsRoot(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		expBool bool
	}{
		{
			name:    "root is root",
			input:   "root",
			expBool: true,
		},
		{
			name:    "agent is not root",
			input:   "agent-aws",
			expBool: false,
		},
		{
			name:    "empty string is not root",
			input:   "",
			expBool: false,
		},
		{
			name:    "ROOT uppercase is not root",
			input:   "ROOT",
			expBool: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			result := authz.IsRoot(tt.input)

			// then
			assert.Equal(t, tt.expBool, result)
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name          string
		selfName      string
		subAgentNames []string
		expErr        error
	}{
		{
			name:          "valid with sub-agents",
			selfName:      "agent-aws",
			subAgentNames: []string{"agent-leaf"},
			expErr:        nil,
		},
		{
			name:          "valid with nil sub-agents",
			selfName:      "agent-aws",
			subAgentNames: nil,
			expErr:        nil,
		},
		{
			name:          "valid with empty sub-agents",
			selfName:      "agent-aws",
			subAgentNames: []string{},
			expErr:        nil,
		},
		{
			name:          "valid root",
			selfName:      "root",
			subAgentNames: []string{"agent-aws", "agent-gcp"},
			expErr:        nil,
		},
		{
			name:          "empty selfName",
			selfName:      "",
			subAgentNames: []string{},
			expErr:        authz.ErrSelfNameEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			authZ, err := authz.New(tt.selfName, tt.subAgentNames)

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				assert.Nil(t, authZ)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authZ)
			}
		})
	}
}

func TestAuthorize(t *testing.T) {
	// Hierarchy: K0 -> K1 -> K2 -> K3 -> K4
	// Root manages K0->K1, has sub-agents: [agent-aws, agent-gcp]
	// agent-aws manages K2->K3, has sub-agents: [agent-leaf]
	// agent-gcp manages K2->K3, has sub-agents: []
	// agent-leaf manages K4, has sub-agents: []

	tests := []struct {
		name          string
		selfName      string
		subAgentNames []string
		ctx           authz.Context
		expErr        error
	}{
		// Rule 1: Root can call anyone
		{
			name:          "root can call agent-aws",
			selfName:      "agent-aws",
			subAgentNames: []string{"agent-leaf"},
			ctx: authz.Context{
				Caller:    "root",
				Target:    "agent-aws",
				Operation: "register",
			},
		},
		{
			name:          "root can call agent-leaf",
			selfName:      "agent-leaf",
			subAgentNames: []string{},
			ctx: authz.Context{
				Caller:    "root",
				Target:    "agent-leaf",
				Operation: "register",
			},
		},
		{
			name:          "root can call root",
			selfName:      "root",
			subAgentNames: []string{"agent-aws", "agent-gcp"},
			ctx: authz.Context{
				Caller:    "root",
				Target:    "root",
				Operation: "internal",
			},
		},

		// Rule 2: Anyone can call root
		{
			name:          "agent-aws can call root",
			selfName:      "root",
			subAgentNames: []string{"agent-aws", "agent-gcp"},
			ctx: authz.Context{
				Caller:    "agent-aws",
				Target:    "root",
				Operation: "heartbeat",
			},
		},
		{
			name:          "agent-leaf can call root",
			selfName:      "root",
			subAgentNames: []string{"agent-aws", "agent-gcp"},
			ctx: authz.Context{
				Caller:    "agent-leaf",
				Target:    "root",
				Operation: "heartbeat",
			},
		},
		{
			name:          "unknown agent can call root",
			selfName:      "root",
			subAgentNames: []string{"agent-aws", "agent-gcp"},
			ctx: authz.Context{
				Caller:    "unknown-agent",
				Target:    "root",
				Operation: "heartbeat",
			},
		},

		// Rule 3: Sub-agent can call parent
		{
			name:          "agent-leaf can call agent-aws (sub-agent calls parent)",
			selfName:      "agent-aws",
			subAgentNames: []string{"agent-leaf"},
			ctx: authz.Context{
				Caller:    "agent-leaf",
				Target:    "agent-aws",
				Operation: "unwrap-key",
			},
		},

		// Rule 4: Deny other combinations
		{
			name:          "agent-aws cannot call agent-leaf (parent cannot call sub-agent)",
			selfName:      "agent-leaf",
			subAgentNames: []string{},
			ctx: authz.Context{
				Caller:    "agent-aws",
				Target:    "agent-leaf",
				Operation: "some-op",
			},
			expErr: authz.ErrUnauthorized,
		},
		{
			name:          "agent-aws cannot call agent-gcp (siblings cannot call each other)",
			selfName:      "agent-gcp",
			subAgentNames: []string{},
			ctx: authz.Context{
				Caller:    "agent-aws",
				Target:    "agent-gcp",
				Operation: "some-op",
			},
			expErr: authz.ErrUnauthorized,
		},
		{
			name:          "agent-gcp cannot call agent-aws (siblings cannot call each other)",
			selfName:      "agent-aws",
			subAgentNames: []string{"agent-leaf"},
			ctx: authz.Context{
				Caller:    "agent-gcp",
				Target:    "agent-aws",
				Operation: "some-op",
			},
			expErr: authz.ErrUnauthorized,
		},
		{
			name:          "agent-leaf cannot call agent-gcp (no relationship)",
			selfName:      "agent-gcp",
			subAgentNames: []string{},
			ctx: authz.Context{
				Caller:    "agent-leaf",
				Target:    "agent-gcp",
				Operation: "some-op",
			},
			expErr: authz.ErrUnauthorized,
		},

		// Edge cases
		{
			name:          "nil subAgentNames - agent calling non-root",
			selfName:      "agent-aws",
			subAgentNames: nil,
			ctx: authz.Context{
				Caller:    "agent-leaf",
				Target:    "agent-aws",
				Operation: "unwrap-key",
			},
			expErr: authz.ErrUnauthorized,
		},
		{
			name:          "empty subAgentNames - agent calling non-root",
			selfName:      "agent-aws",
			subAgentNames: []string{},
			ctx: authz.Context{
				Caller:    "agent-leaf",
				Target:    "agent-aws",
				Operation: "unwrap-key",
			},
			expErr: authz.ErrUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			authZ, err := authz.New(tt.selfName, tt.subAgentNames)
			assert.NoError(t, err)

			// when
			err = authZ.Authorize(tt.ctx)

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
