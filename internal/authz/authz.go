package authz

import (
	"errors"
	"fmt"
)

const rootName = "root"

var (
	// ErrUnauthorized is returned when no trust relationship exists between caller and target.
	ErrUnauthorized = errors.New("unauthorized: no trust relationship")
	// ErrSelfNameEmpty is returned when selfName is empty.
	ErrSelfNameEmpty = errors.New("selfName cannot be empty")
)

// AuthZ provides topology-based authorization for agent-to-agent communication.
type AuthZ struct {
	selfName      string
	subAgentNames map[string]struct{}
}

// Context contains the information needed to authorize a connection.
type Context struct {
	Caller    string // CN from client certificate
	Target    string // CN of the server being called
	Operation string // Operation being performed (e.g., "announce-key", "heartbeat")
}

// New creates a new AuthZ instance.
// selfName is the identity of the current agent ("root" or agent name).
// subAgentNames is the list of agent names that are authorized to call this agent.
// Returns an error if selfName is empty.
func New(selfName string, subAgentNames []string) (*AuthZ, error) {
	if selfName == "" {
		return nil, ErrSelfNameEmpty
	}
	subAgents := make(map[string]struct{}, len(subAgentNames))
	for _, name := range subAgentNames {
		subAgents[name] = struct{}{}
	}
	return &AuthZ{
		selfName:      selfName,
		subAgentNames: subAgents,
	}, nil
}

// IsRoot returns true if the given name is the root identity.
func IsRoot(name string) bool {
	return name == rootName
}

// Authorize checks if the caller is authorized to communicate with the target.
// Returns nil if authorized, or an error describing why authorization failed.
//
// Authorization rules:
//  1. Root can call anyone
//  2. Anyone can call root
//  3. A sub-agent can call its parent (caller must be in parent's subAgentNames)
//  4. All other combinations are denied
func (a *AuthZ) Authorize(ctx Context) error {
	// Rule 1: Root can call anyone
	if IsRoot(ctx.Caller) {
		return nil
	}

	// Rule 2: Anyone can call root
	if IsRoot(ctx.Target) {
		return nil
	}

	// Rule 3: Sub-agent can call parent (caller must be in my subAgentNames)
	if _, ok := a.subAgentNames[ctx.Caller]; ok {
		return nil
	}

	// Rule 4: Deny all other combinations
	return fmt.Errorf("%w: %q is not allowed to call %q", ErrUnauthorized, ctx.Caller, ctx.Target)
}
