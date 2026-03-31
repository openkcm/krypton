package keylifecycle_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/keylifecycle"
)

var allKeyStates = []keylifecycle.State{
	keylifecycle.StatePreActivation,
	keylifecycle.StateActive,
	keylifecycle.StateSuspended,
	keylifecycle.StateDeactivated,
	keylifecycle.StateCompromised,
	keylifecycle.StateDestroyed,
}

var allKeyOperations = []keylifecycle.Operation{
	keylifecycle.OperationEncrypt,
	keylifecycle.OperationDecrypt,
	keylifecycle.OperationWrap,
	keylifecycle.OperationUnwrap,
}

func TestKeyLifeCycleStateTransitions(t *testing.T) {
	t.Parallel()

	tts := []struct {
		from             keylifecycle.State
		validTransitions map[keylifecycle.State]struct{}
	}{
		{
			from: keylifecycle.StatePreActivation,
			validTransitions: map[keylifecycle.State]struct{}{
				keylifecycle.StateDestroyed:   {},
				keylifecycle.StateActive:      {},
				keylifecycle.StateCompromised: {},
			},
		},
		{
			from: keylifecycle.StateActive,
			validTransitions: map[keylifecycle.State]struct{}{
				keylifecycle.StateDestroyed:   {},
				keylifecycle.StateDeactivated: {},
				keylifecycle.StateSuspended:   {},
				keylifecycle.StateCompromised: {},
			},
		},
		{
			from: keylifecycle.StateSuspended,
			validTransitions: map[keylifecycle.State]struct{}{
				keylifecycle.StateDestroyed:   {},
				keylifecycle.StateDeactivated: {},
				keylifecycle.StateCompromised: {},
				keylifecycle.StateActive:      {},
			},
		},
		{
			from: keylifecycle.StateDeactivated,
			validTransitions: map[keylifecycle.State]struct{}{
				keylifecycle.StateDestroyed:   {},
				keylifecycle.StateCompromised: {},
			},
		},
		{
			from: keylifecycle.StateCompromised,
			validTransitions: map[keylifecycle.State]struct{}{
				keylifecycle.StateDestroyed: {},
			},
		},
		{
			from:             keylifecycle.StateDestroyed,
			validTransitions: map[keylifecycle.State]struct{}{},
		},
		{
			from:             "invalid-state",
			validTransitions: map[keylifecycle.State]struct{}{},
		},
	}

	t.Run("ValidateTransition", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tts {
			for _, to := range allKeyStates {
				_, isValid := tt.validTransitions[to]

				t.Run(fmt.Sprintf("[%s] to [%s] transition=%t", tt.from, to, isValid), func(t *testing.T) {
					t.Parallel()

					// when
					actResult := keylifecycle.ValidateTransition(tt.from, to)

					// then
					if isValid {
						assert.NoError(t, actResult, "unexpected transition from %s to %s", tt.from, to)
					} else {
						assert.ErrorIs(t, actResult, keylifecycle.ErrInvalidKeyStateTransition, "expected invalid transition from %s to %s", tt.from, to)
					}
				})
			}
		}
	})

	t.Run("GetAllowedTransitions", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tts {
			// given
			expResult := make([]keylifecycle.State, 0, len(tt.validTransitions))
			for k := range tt.validTransitions {
				expResult = append(expResult, k)
			}

			t.Run(fmt.Sprintf("from [%s] allowed transition=%v", tt.from, expResult), func(t *testing.T) {
				t.Parallel()

				// when
				actResult := keylifecycle.GetAllowedTransitions(tt.from)

				// then
				assert.ElementsMatch(t, expResult, actResult, "unexpected allowed transitions from %s", tt.from)
			})
		}
	})
}

func TestKeyLifeCycleOperations(t *testing.T) {
	t.Parallel()

	tts := []struct {
		state           keylifecycle.State
		validOperations map[keylifecycle.Operation]struct{}
	}{
		{
			state:           keylifecycle.StatePreActivation,
			validOperations: map[keylifecycle.Operation]struct{}{},
		},
		{
			state: keylifecycle.StateActive,
			validOperations: map[keylifecycle.Operation]struct{}{
				keylifecycle.OperationEncrypt: {},
				keylifecycle.OperationDecrypt: {},
				keylifecycle.OperationWrap:    {},
				keylifecycle.OperationUnwrap:  {},
			},
		},
		{
			state: keylifecycle.StateSuspended,
			validOperations: map[keylifecycle.Operation]struct{}{
				keylifecycle.OperationDecrypt: {},
				keylifecycle.OperationUnwrap:  {},
			},
		},
		{
			state: keylifecycle.StateDeactivated,
			validOperations: map[keylifecycle.Operation]struct{}{
				keylifecycle.OperationDecrypt: {},
				keylifecycle.OperationUnwrap:  {},
			},
		},
		{
			state: keylifecycle.StateCompromised,
			validOperations: map[keylifecycle.Operation]struct{}{
				keylifecycle.OperationDecrypt: {},
				keylifecycle.OperationUnwrap:  {},
			},
		},
		{
			state:           keylifecycle.StateDestroyed,
			validOperations: map[keylifecycle.Operation]struct{}{},
		},
		{
			state:           "invalid-state",
			validOperations: map[keylifecycle.Operation]struct{}{},
		},
	}

	t.Run("ValidateOperation", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tts {
			for _, op := range allKeyOperations {
				_, isValid := tt.validOperations[op]

				t.Run(fmt.Sprintf("[%s] perform [%s]=%t", tt.state, op, isValid), func(t *testing.T) {
					t.Parallel()

					// when
					actResult := keylifecycle.ValidateOperation(tt.state, op)

					// then
					if isValid {
						assert.NoError(t, actResult, "unexpectedly not allowed to perform %s in state %s", op, tt.state)
					} else {
						assert.ErrorIs(t, actResult, keylifecycle.ErrOperationNotAllowedInState, "expected not allowed to perform %s in state %s", op, tt.state)
					}
				})
			}
		}
	})

	t.Run("GetAllowedOperations", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tts {
			// given
			expResult := make([]keylifecycle.Operation, 0, len(tt.validOperations))
			for k := range tt.validOperations {
				expResult = append(expResult, k)
			}

			t.Run(fmt.Sprintf("in state [%s] allowed operations =%v", tt.state, expResult), func(t *testing.T) {
				t.Parallel()

				// when
				actResult := keylifecycle.GetAllowedOperations(tt.state)

				// then
				assert.ElementsMatch(t, expResult, actResult, "unexpected allowed operations in state %s", tt.state)
			})
		}
	})
}
