package keylifecycle_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
)

var allKeyStates = []model.KeyState{
	model.KeyStatePreActivation,
	model.KeyStateActive,
	model.KeyStateSuspended,
	model.KeyStateDeactivated,
	model.KeyStateCompromised,
	model.KeyStateDestroyed,
	model.KeyStateAnnounceFailed,
}

var allKeyOperations = []spec.KeyUsage{
	spec.KeyUsageEncrypt,
	spec.KeyUsageDecrypt,
	spec.KeyUsageUnwrap,
	spec.KeyUsageWrap,
}

func TestKeyLifecycleStateTransitions(t *testing.T) {
	t.Parallel()

	tts := []struct {
		from             model.KeyState
		validTransitions map[model.KeyState]struct{}
	}{
		{
			from: model.KeyStatePreActivation,
			validTransitions: map[model.KeyState]struct{}{
				model.KeyStateDestroyed:      {},
				model.KeyStateActive:         {},
				model.KeyStateCompromised:    {},
				model.KeyStateAnnounceFailed: {},
			},
		},
		{
			from: model.KeyStateActive,
			validTransitions: map[model.KeyState]struct{}{
				model.KeyStateDestroyed:   {},
				model.KeyStateDeactivated: {},
				model.KeyStateSuspended:   {},
				model.KeyStateCompromised: {},
			},
		},
		{
			from: model.KeyStateSuspended,
			validTransitions: map[model.KeyState]struct{}{
				model.KeyStateDestroyed:   {},
				model.KeyStateDeactivated: {},
				model.KeyStateCompromised: {},
				model.KeyStateActive:      {},
			},
		},
		{
			from: model.KeyStateDeactivated,
			validTransitions: map[model.KeyState]struct{}{
				model.KeyStateDestroyed:   {},
				model.KeyStateCompromised: {},
			},
		},
		{
			from: model.KeyStateCompromised,
			validTransitions: map[model.KeyState]struct{}{
				model.KeyStateDestroyed: {},
			},
		},
		{
			from:             model.KeyStateDestroyed,
			validTransitions: map[model.KeyState]struct{}{},
		},
		{
			from: model.KeyStateAnnounceFailed,
			validTransitions: map[model.KeyState]struct{}{
				model.KeyStateDestroyed: {},
			},
		},
		{
			from:             "invalid-state",
			validTransitions: map[model.KeyState]struct{}{},
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
			expResult := make([]model.KeyState, 0, len(tt.validTransitions))
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
		state           model.KeyState
		validOperations spec.KeyUsage
	}{
		{
			state:           model.KeyStatePreActivation,
			validOperations: spec.KeyUsageNone,
		},
		{
			state:           model.KeyStateActive,
			validOperations: spec.KeyUsageDecrypt | spec.KeyUsageEncrypt | spec.KeyUsageWrap | spec.KeyUsageUnwrap,
		},
		{
			state:           model.KeyStateSuspended,
			validOperations: spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		},
		{
			state:           model.KeyStateDeactivated,
			validOperations: spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		},
		{
			state:           model.KeyStateCompromised,
			validOperations: spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		},
		{
			state:           model.KeyStateDestroyed,
			validOperations: spec.KeyUsageNone,
		},
		{
			state:           model.KeyStateAnnounceFailed,
			validOperations: spec.KeyUsageNone,
		},
		{
			state:           "invalid-state",
			validOperations: spec.KeyUsageNone,
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
