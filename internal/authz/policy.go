package authz

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/authn"
	"github.com/openkcm/krypton/internal/clock"
)

// Effect determines whether a statement allows or denies access.
type Effect string

const (
	EffectAllow Effect = "Allow"
	EffectDeny  Effect = "Deny"
)

// Policy represents an authorization policy that determines what actions
// principals can perform on which resources.
type Policy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Statements  []Statement       `json:"statements"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	CreatedBy   string            `json:"created_by"`
	CreatedAt   clock.UnixNano    `json:"created_at"`
	UpdatedAt   clock.UnixNano    `json:"updated_at"`
}

// Statement is a single authorization rule within a policy.
type Statement struct {
	Effect     Effect            `json:"effect"`
	Principals []IdentityPattern `json:"principals"`
	Actions    []ActionPattern   `json:"actions"`
	Resources  []IdentityPattern `json:"resources"`
}

// Request represents an authorization question:
// Can this principal perform this action on this resource?
type Request struct {
	Principal authn.Identity
	Action    Action
	Resource  authn.Identity
}

// Action represents a Krypton operation.
type Action string

// Decision is the result of policy evaluation.
type Decision struct {
	Allow  bool
	Reason string
}

// PolicyEngine evaluates authorization policies to produce access decisions.
type PolicyEngine struct {
	builtins []Policy
	store    PolicyStore
}

// NewPolicyEngine creates a PolicyEngine with builtin policies and a store
// for user-defined policies.
func NewPolicyEngine(builtins []Policy, store PolicyStore) *PolicyEngine {
	return &PolicyEngine{
		builtins: builtins,
		store:    store,
	}
}

// Decide checks whether the request is allowed.
// Evaluation order:
//  1. If any matching statement has Effect=Deny → deny (explicit)
//  2. If any matching statement has Effect=Allow → allow (explicit)
//  3. Otherwise → deny (implicit, no matching allow)
func (e *PolicyEngine) Decide(ctx context.Context, req Request) Decision {
	result, err := e.store.List(ctx, ListPoliciesQuery{})
	if err != nil {
		return Decision{
			Allow:  false,
			Reason: "policy store unavailable: " + err.Error(),
		}
	}

	allPolicies := make([]Policy, 0, len(e.builtins)+len(result.Policies))
	allPolicies = append(allPolicies, e.builtins...)
	allPolicies = append(allPolicies, result.Policies...)

	var firstAllow string

	for i := range allPolicies {
		policy := &allPolicies[i]

		for j := range policy.Statements {
			stmt := &policy.Statements[j]

			if !matchesAnyIdentity(stmt.Principals, req.Principal) {
				continue
			}
			if !matchesAnyAction(stmt.Actions, req.Action) {
				continue
			}
			if !matchesAnyIdentity(stmt.Resources, req.Resource) {
				continue
			}

			switch stmt.Effect {
			case EffectDeny:
				return Decision{
					Allow:  false,
					Reason: "denied by policy: " + policy.Name,
				}

			case EffectAllow:
				if firstAllow == "" {
					firstAllow = policy.Name
				}

			default:
				return Decision{
					Allow:  false,
					Reason: "invalid effect in policy: " + policy.Name,
				}
			}
		}
	}

	if firstAllow != "" {
		return Decision{
			Allow:  true,
			Reason: "allowed by policy: " + firstAllow,
		}
	}

	return Decision{
		Allow:  false,
		Reason: "no matching allow policy",
	}
}

var (
	// ErrPolicyNotFound is returned when a policy cannot be found.
	ErrPolicyNotFound = errors.New("policy not found")

	// ErrPolicyQueryInvalid is returned when a query is missing required fields.
	ErrPolicyQueryInvalid = errors.New("policy query invalid")
)

// PolicyStore provides CRUDL operations for user-defined policies.
type PolicyStore interface {
	Create(ctx context.Context, q CreatePolicyQuery) (CreatePolicyResult, error)
	Get(ctx context.Context, q GetPolicyQuery) (GetPolicyResult, error)
	Update(ctx context.Context, q UpdatePolicyQuery) (UpdatePolicyResult, error)
	Delete(ctx context.Context, q DeletePolicyQuery) error
	List(ctx context.Context, q ListPoliciesQuery) (ListPoliciesResult, error)
}

type (
	// CreatePolicyQuery is the input for creating a new policy.
	CreatePolicyQuery struct {
		Policy Policy
	}

	// CreatePolicyResult is the output of a successful policy creation.
	CreatePolicyResult struct {
		Policy Policy
	}

	// GetPolicyQuery is the input for retrieving a policy by ID.
	GetPolicyQuery struct {
		ID string
	}

	// GetPolicyResult is the output of a successful policy retrieval.
	GetPolicyResult struct {
		Policy Policy
	}

	// UpdatePolicyQuery is the input for updating an existing policy.
	UpdatePolicyQuery struct {
		Policy Policy
	}

	// UpdatePolicyResult is the output of a successful policy update.
	UpdatePolicyResult struct {
		Policy Policy
	}

	// DeletePolicyQuery is the input for deleting a policy by ID.
	DeletePolicyQuery struct {
		ID string
	}

	// ListPoliciesQuery is the input for listing policies.
	ListPoliciesQuery struct{}

	// ListPoliciesResult is the output of a successful policy listing.
	ListPoliciesResult struct {
		Policies []Policy
	}
)
