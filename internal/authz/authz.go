package authz

import (
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/spec"
)

var (
	// ErrUnauthorized is returned when no trust relationship exists between caller and target.
	ErrUnauthorized = errors.New("unauthorized: no trust relationship")
	// ErrTrustDomainMismatch is returned when caller and target have different trust domains.
	ErrTrustDomainMismatch = errors.New("unauthorized: trust domain mismatch")
)

// AuthZ provides topology-based authorization for agent-to-agent communication.
type AuthZ struct {
	selfID      spec.KryptonID
	subAgentIDs map[string]struct{} // keyed by PrincipalName()
}

// Context contains the information needed to authorize a connection.
type Context struct {
	CallerID spec.KryptonID // Identity from client certificate URI SAN
	TargetID spec.KryptonID // Identity of the server being called
}

// New creates a new AuthZ instance.
// selfID is the identity of the current agent.
// subAgentIDs is the list of agent identities that are authorized to call this agent.
func New(selfID spec.KryptonID, subAgentIDs []spec.KryptonID) *AuthZ {
	subAgents := make(map[string]struct{}, len(subAgentIDs))
	for _, id := range subAgentIDs {
		subAgents[id.PrincipalName()] = struct{}{}
	}
	return &AuthZ{
		selfID:      selfID,
		subAgentIDs: subAgents,
	}
}

// authorize checks if the caller is authorized to communicate with the target.
// Returns nil if authorized, or an error describing why authorization failed.
//
// Authorization rules:
//  0. Trust domains must match
//  1. Root can call anyone
//  2. Anyone can call root
//  3. A sub-agent can call its parent (caller must be in parent's subAgentIDs)
//  4. All other combinations are denied
func (a *AuthZ) authorize(ctx Context) error {
	// Rule 0: Trust domains must match
	if ctx.CallerID.TrustDomain != ctx.TargetID.TrustDomain {
		return fmt.Errorf("%w: caller %q, target %q",
			ErrTrustDomainMismatch, ctx.CallerID.TrustDomain, ctx.TargetID.TrustDomain)
	}

	// Rule 1: Root can call anyone
	if ctx.CallerID.IsRoot() {
		return nil
	}

	// Rule 2: Anyone can call root
	if ctx.TargetID.IsRoot() {
		return nil
	}

	// Rule 3: Sub-agent can call parent (caller must be in my subAgentIDs)
	if _, ok := a.subAgentIDs[ctx.CallerID.PrincipalName()]; ok {
		return nil
	}

	// Rule 4: Deny all other combinations
	return fmt.Errorf("%w: %q is not allowed to call %q",
		ErrUnauthorized, ctx.CallerID.PrincipalName(), ctx.TargetID.PrincipalName())
}
