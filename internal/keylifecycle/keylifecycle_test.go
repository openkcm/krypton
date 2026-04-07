package keylifecycle_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/model"
)

var allKeyStates = []keylifecycle.State{
	keylifecycle.StatePreActivation,
	keylifecycle.StateActive,
	keylifecycle.StateSuspended,
	keylifecycle.StateDeactivated,
	keylifecycle.StateCompromised,
	keylifecycle.StateDestroyed,
}

var allKeyOperations = []model.KeyUsage{
	model.KeyUsageEncrypt,
	model.KeyUsageDecrypt,
	model.KeyUsageUnwrap,
	model.KeyUsageWrap,
}

func TestKeyLifecycleStateTransitions(t *testing.T) {
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

func TestKeyLifecycleKeyUsages(t *testing.T) {
	t.Parallel()

	tts := []struct {
		state           keylifecycle.State
		validOperations model.KeyUsage
	}{
		{
			state:           keylifecycle.StatePreActivation,
			validOperations: model.KeyUsageNone,
		},
		{
			state:           keylifecycle.StateActive,
			validOperations: model.KeyUsageDecrypt | model.KeyUsageEncrypt | model.KeyUsageWrap | model.KeyUsageUnwrap,
		},
		{
			state:           keylifecycle.StateSuspended,
			validOperations: model.KeyUsageDecrypt | model.KeyUsageUnwrap,
		},
		{
			state:           keylifecycle.StateDeactivated,
			validOperations: model.KeyUsageDecrypt | model.KeyUsageUnwrap,
		},
		{
			state:           keylifecycle.StateCompromised,
			validOperations: model.KeyUsageDecrypt | model.KeyUsageUnwrap,
		},
		{
			state:           keylifecycle.StateDestroyed,
			validOperations: model.KeyUsageNone,
		},
		{
			state:           "invalid-state",
			validOperations: model.KeyUsageNone,
		},
	}

	t.Run("ValidateKeyUsage", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tts {
			for _, op := range allKeyOperations {
				isValid := tt.validOperations.Has(op)

				t.Run(fmt.Sprintf("[%s] perform [%s]=%t", tt.state, op, isValid), func(t *testing.T) {
					t.Parallel()

					// when
					actResult := keylifecycle.ValidateKeyUsage(tt.state, op)

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

	t.Run("GetAllowedKeyUsages", func(t *testing.T) {
		t.Parallel()
		for _, tt := range tts {
			// given
			expResult := tt.validOperations

			t.Run(fmt.Sprintf("in state [%s] allowed operations =%v", tt.state, expResult), func(t *testing.T) {
				t.Parallel()

				// when
				actResult := keylifecycle.GetAllowedKeyUsages(tt.state)

				// then
				assert.Equal(t, expResult, actResult, "unexpected allowed operations in state %s", tt.state)
			})
		}
	})
}
