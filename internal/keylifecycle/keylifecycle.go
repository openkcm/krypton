// Package keylifecycle manages cryptographic key lifecycle states and
// transition validation per NIST SP 800-57 Part 1 Rev 5.
package keylifecycle

import (
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/spec"
)

type (
	// State represents a lifecycle state of a cryptographic key.
	State string
)

// Key lifecycle states per NIST SP 800-57.
const (
	// StatePreActivation: key generated but not yet in use.
	StatePreActivation State = "pre-activation"
	// StateActive: key is in normal operational use.
	StateActive State = "active"
	// StateSuspended: key temporarily disabled; decrypt/unwrap only.
	StateSuspended State = "suspended"
	// StateDeactivated: key retired; decrypt/unwrap only.
	StateDeactivated State = "deactivated"
	// StateCompromised: key integrity suspect; decrypt/unwrap only.
	StateCompromised State = "compromised"
	// StateDestroyed: key material erased; no operations allowed.
	StateDestroyed State = "destroyed"
)

// lifecycle holds allowed state transitions and per-state permitted operations.
type lifecycle struct {
	transitions map[State]map[State]struct{}
	stateUsages map[State]spec.KeyUsage
}

// Sentinel errors for lifecycle validation.
var (
	ErrInvalidKeyStateTransition  = errors.New("invalid key state transition")
	ErrOperationNotAllowedInState = errors.New("operation not allowed in current key state")
)

// defaultLifecycle encodes the NIST SP 800-57 state machine used by all public functions.
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
	stateUsages: map[State]spec.KeyUsage{
		StatePreActivation: spec.KeyUsageNone,
		StateActive:        spec.KeyUsageEncrypt | spec.KeyUsageDecrypt | spec.KeyUsageUnwrap | spec.KeyUsageWrap,
		StateSuspended:     spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		StateDeactivated:   spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		StateCompromised:   spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		StateDestroyed:     spec.KeyUsageNone,
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

// ValidateKeyUsage checks whether operation op is permitted in state s.
func ValidateKeyUsage(s State, op spec.KeyUsage) error {
	ops, ok := defaultLifecycle.stateUsages[s]
	if !ok {
		return fmt.Errorf("invalid state: %s: %w", s, ErrOperationNotAllowedInState)
	}

	ok = ops.Has(op)
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

// GetAllowedKeyUsages returns the permitted operations for the given state.
func GetAllowedKeyUsages(s State) spec.KeyUsage {
	ops, ok := defaultLifecycle.stateUsages[s]
	if !ok {
		return spec.KeyUsageNone
	}

	return ops
}
