// Package keylifecycle manages cryptographic key lifecycle states and
// transition validation per NIST SP 800-57 Part 1 Rev 5.
package keylifecycle

import (
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
)

// lifecycle holds allowed state transitions and per-state permitted operations.
type lifecycle struct {
	transitions map[model.KeyLifeCycleState]map[model.KeyLifeCycleState]struct{}
	stateUsages map[model.KeyLifeCycleState]spec.KeyUsage
}

// Sentinel errors for lifecycle validation.
var (
	ErrInvalidKeyStateTransition  = errors.New("invalid key state transition")
	ErrOperationNotAllowedInState = errors.New("operation not allowed in current key state")
)

// defaultLifecycle encodes the NIST SP 800-57 state machine used by all public functions.
var defaultLifecycle = lifecycle{
	transitions: map[model.KeyLifeCycleState]map[model.KeyLifeCycleState]struct{}{
		model.KeyLifeCyclePreActivation: {
			model.KeyLifeCycleDestroyed:   {},
			model.KeyLifeCycleActive:      {},
			model.KeyLifeCycleCompromised: {},
		},
		model.KeyLifeCycleActive: {
			model.KeyLifeCycleDestroyed:   {},
			model.KeyLifeCycleDeactivated: {},
			model.KeyLifeCycleSuspended:   {},
			model.KeyLifeCycleCompromised: {},
		},
		model.KeyLifeCycleSuspended: {
			model.KeyLifeCycleDestroyed:   {},
			model.KeyLifeCycleDeactivated: {},
			model.KeyLifeCycleCompromised: {},
			model.KeyLifeCycleActive:      {},
		},
		model.KeyLifeCycleDeactivated: {
			model.KeyLifeCycleDestroyed:   {},
			model.KeyLifeCycleCompromised: {},
		},
		model.KeyLifeCycleCompromised: {
			model.KeyLifeCycleDestroyed: {},
		},
		model.KeyLifeCycleDestroyed: {},
	},
	stateUsages: map[model.KeyLifeCycleState]spec.KeyUsage{
		model.KeyLifeCyclePreActivation: spec.KeyUsageNone,
		model.KeyLifeCycleActive:        spec.KeyUsageEncrypt | spec.KeyUsageDecrypt | spec.KeyUsageUnwrap | spec.KeyUsageWrap,
		model.KeyLifeCycleSuspended:     spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		model.KeyLifeCycleDeactivated:   spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		model.KeyLifeCycleCompromised:   spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		model.KeyLifeCycleDestroyed:     spec.KeyUsageNone,
	},
}

// ValidateTransition checks whether transitioning from one state to another is allowed.
func ValidateTransition(from, to model.KeyLifeCycleState) error {
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
func ValidateKeyUsage(s model.KeyLifeCycleState, op spec.KeyUsage) error {
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
func GetAllowedTransitions(s model.KeyLifeCycleState) []model.KeyLifeCycleState {
	ts, ok := defaultLifecycle.transitions[s]
	if !ok {
		return []model.KeyLifeCycleState{}
	}

	rs := make([]model.KeyLifeCycleState, 0, len(ts))
	for k := range ts {
		rs = append(rs, k)
	}
	return rs
}

// GetAllowedKeyUsages returns the permitted operations for the given state.
func GetAllowedKeyUsages(s model.KeyLifeCycleState) spec.KeyUsage {
	ops, ok := defaultLifecycle.stateUsages[s]
	if !ok {
		return spec.KeyUsageNone
	}

	return ops
}
