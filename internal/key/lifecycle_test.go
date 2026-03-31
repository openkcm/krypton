package key_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/key"
)

var allKeyStates = []key.State{
	key.StatePreActivation,
	key.StateActive,
	key.StateSuspended,
	key.StateDeactivated,
	key.StateCompromised,
	key.StateDestroyed,
}

var allKeyOperations = []key.Operation{
	key.OperationEncrypt,
	key.OperationDecrypt,
	key.OperationWrap,
	key.OperationUnwrap,
}

func TestNewLifeCycle(t *testing.T) {
	t.Parallel()

	// given when
	lifecycle := key.NewLifecycle()

	// then
	assert.NotNil(t, lifecycle)
}

func TestKeyLifeCycleStateTransitions(t *testing.T) {
	t.Parallel()

	// given
	subj := key.NewLifecycle()

	tts := []struct {
		from             key.State
		validTransitions map[key.State]struct{}
	}{
		{
			from: key.StatePreActivation,
			validTransitions: map[key.State]struct{}{
				key.StateDestroyed:   {},
				key.StateActive:      {},
				key.StateCompromised: {},
			},
		},
		{
			from: key.StateActive,
			validTransitions: map[key.State]struct{}{
				key.StateDestroyed:   {},
				key.StateDeactivated: {},
				key.StateSuspended:   {},
				key.StateCompromised: {},
			},
		},
		{
			from: key.StateSuspended,
			validTransitions: map[key.State]struct{}{
				key.StateDestroyed:   {},
				key.StateDeactivated: {},
				key.StateCompromised: {},
				key.StateActive:      {},
			},
		},
		{
			from: key.StateDeactivated,
			validTransitions: map[key.State]struct{}{
				key.StateDestroyed:   {},
				key.StateCompromised: {},
			},
		},
		{
			from: key.StateCompromised,
			validTransitions: map[key.State]struct{}{
				key.StateDestroyed: {},
			},
		},
		{
			from:             key.StateDestroyed,
			validTransitions: map[key.State]struct{}{},
		},
		{
			from:             "invalid-state",
			validTransitions: map[key.State]struct{}{},
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
					actResult := subj.ValidateTransition(tt.from, to)

					// then
					if isValid {
						assert.NoError(t, actResult, "unexpected transition from %s to %s", tt.from, to)
					} else {
						assert.ErrorIs(t, actResult, key.ErrInvalidKeyStateTransition, "expected invalid transition from %s to %s", tt.from, to)
					}
				})
			}
		}
	})

	t.Run("GetAllowedTransitions", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tts {
			// given
			expResult := make([]key.State, 0, len(tt.validTransitions))
			for k := range tt.validTransitions {
				expResult = append(expResult, k)
			}

			t.Run(fmt.Sprintf("from [%s] allowed transition=%v", tt.from, expResult), func(t *testing.T) {
				t.Parallel()

				// when
				actResult := subj.GetAllowedTransitions(tt.from)

				// then
				assert.ElementsMatch(t, expResult, actResult, "unexpected allowed transitions from %s", tt.from)
			})
		}
	})
}

func TestKeyLifeCycleOperations(t *testing.T) {
	t.Parallel()

	// given
	subj := key.NewLifecycle()

	tts := []struct {
		state           key.State
		validOperations map[key.Operation]struct{}
	}{
		{
			state:           key.StatePreActivation,
			validOperations: map[key.Operation]struct{}{},
		},
		{
			state: key.StateActive,
			validOperations: map[key.Operation]struct{}{
				key.OperationEncrypt: {},
				key.OperationDecrypt: {},
				key.OperationWrap:    {},
				key.OperationUnwrap:  {},
			},
		},
		{
			state: key.StateSuspended,
			validOperations: map[key.Operation]struct{}{
				key.OperationDecrypt: {},
				key.OperationUnwrap:  {},
			},
		},
		{
			state: key.StateDeactivated,
			validOperations: map[key.Operation]struct{}{
				key.OperationDecrypt: {},
				key.OperationUnwrap:  {},
			},
		},
		{
			state: key.StateCompromised,
			validOperations: map[key.Operation]struct{}{
				key.OperationDecrypt: {},
				key.OperationUnwrap:  {},
			},
		},
		{
			state:           key.StateDestroyed,
			validOperations: map[key.Operation]struct{}{},
		},
		{
			state:           "invalid-state",
			validOperations: map[key.Operation]struct{}{},
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
					actResult := subj.ValidateOperation(tt.state, op)

					// then
					if isValid {
						assert.NoError(t, actResult, "unexpectedly not allowed to perform %s in state %s", op, tt.state)
					} else {
						assert.ErrorIs(t, actResult, key.ErrOperationNotAllowedInState, "expected not allowed to perform %s in state %s", op, tt.state)
					}
				})
			}
		}
	})

	t.Run("GetAllowedOperations", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tts {
			// given
			expResult := make([]key.Operation, 0, len(tt.validOperations))
			for k := range tt.validOperations {
				expResult = append(expResult, k)
			}

			t.Run(fmt.Sprintf("in state [%s] allowed operations =%v", tt.state, expResult), func(t *testing.T) {
				t.Parallel()

				// when
				actResult := subj.GetAllowedOperations(tt.state)

				// then
				assert.ElementsMatch(t, expResult, actResult, "unexpected allowed operations in state %s", tt.state)
			})
		}
	})
}
