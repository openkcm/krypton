// Package keylifecycle provides key lifecycle state management and transition validation.
package keylifecycle

import (
	"errors"
	"fmt"
)

type (
	// Operation represents a cryptographic operation a key can perform.
	Operation string
	// State represents a lifecycle state of a cryptographic key.
	State string
)

// Key lifecycle states.
// The lifecycle states and transitions are based on the NIST SP 800-57 Part 1, Revision 5.
const (
	StatePreActivation State = "pre-activation"
	StateActive        State = "active"
	StateSuspended     State = "suspended"
	StateDeactivated   State = "deactivated"
	StateCompromised   State = "compromised"
	StateDestroyed     State = "destroyed"
)

// Supported cryptographic key operations.
const (
	OperationEncrypt Operation = "encrypt"
	OperationDecrypt Operation = "decrypt"
	OperationWrap    Operation = "wrap"
	OperationUnwrap  Operation = "unwrap"
)

// lifecycle defines allowed state transitions and per-state permitted operations for a cryptographic key.
type lifecycle struct {
	transitions map[State]map[State]struct{}
	operations  map[State]map[Operation]struct{}
}

// Sentinel errors for lifecycle validation.
var (
	ErrInvalidKeyStateTransition  = errors.New("invalid key state transition")
	ErrOperationNotAllowedInState = errors.New("operation not allowed in current key state")
)

var defaultLifecycle = lifecycle{
	transitions: map[State]map[State]struct{}{
		StatePreActivation: {
			StateDestroyed:   {},
			StateActive:      {},
			StateCompromised: {},
		},
		StateActive: {
			StateDestroyed:   {},
			StateDeactivated: {},
			StateSuspended:   {},
			StateCompromised: {},
		},
		StateSuspended: {
			StateDestroyed:   {},
			StateDeactivated: {},
			StateCompromised: {},
			StateActive:      {},
		},
		StateDeactivated: {
			StateDestroyed:   {},
			StateCompromised: {},
		},
		StateCompromised: {
			StateDestroyed: {},
		},
		StateDestroyed: {},
	},
	operations: map[State]map[Operation]struct{}{
		StatePreActivation: {},
		StateActive: {
			OperationEncrypt: {},
			OperationDecrypt: {},
			OperationWrap:    {},
			OperationUnwrap:  {},
		},
		StateSuspended: {
			OperationDecrypt: {},
			OperationUnwrap:  {},
		},
		StateDeactivated: {
			OperationDecrypt: {},
			OperationUnwrap:  {},
		},
		StateCompromised: {
			OperationDecrypt: {},
			OperationUnwrap:  {},
		},
		StateDestroyed: {},
	},
}

// ValidateTransition checks whether transitioning from one state to another is allowed.
func ValidateTransition(from, to State) error {
	ts, ok := defaultLifecycle.transitions[from]
	if !ok {
		return fmt.Errorf("invalid from state: %s: %w", from, ErrInvalidKeyStateTransition)
	}

	_, ok = ts[to]
	if !ok {
		return fmt.Errorf("cannot transition from %s to %s: %w", from, to, ErrInvalidKeyStateTransition)
	}
	return nil
}

// ValidateOperation checks whether the given operation is permitted in the given state.
func ValidateOperation(s State, op Operation) error {
	ops, ok := defaultLifecycle.operations[s]
	if !ok {
		return fmt.Errorf("invalid state: %s: %w", s, ErrOperationNotAllowedInState)
	}

	_, ok = ops[op]
	if !ok {
		return fmt.Errorf("operation %s not allowed in state %s: %w", op, s, ErrOperationNotAllowedInState)
	}
	return nil
}

// GetAllowedTransitions returns the states reachable from the given state.
func GetAllowedTransitions(s State) []State {
	ts, ok := defaultLifecycle.transitions[s]
	if !ok {
		return []State{}
	}

	rs := make([]State, 0, len(ts))
	for k := range ts {
		rs = append(rs, k)
	}
	return rs
}

// GetAllowedOperations returns the operations permitted in the given state.
func GetAllowedOperations(s State) []Operation {
	ops, ok := defaultLifecycle.operations[s]
	if !ok {
		return []Operation{}
	}

	rs := make([]Operation, 0, len(ops))
	for k := range ops {
		rs = append(rs, k)
	}
	return rs
}
