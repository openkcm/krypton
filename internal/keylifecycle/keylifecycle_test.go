package keylifecycle_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
)

var allKeyStates = []model.KeyLifeCycleState{
	model.KeyLifeCyclePreActivation,
	model.KeyLifeCycleActive,
	model.KeyLifeCycleSuspended,
	model.KeyLifeCycleDeactivated,
	model.KeyLifeCycleCompromised,
	model.KeyLifeCycleDestroyed,
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
		from             model.KeyLifeCycleState
		validTransitions map[model.KeyLifeCycleState]struct{}
	}{
		{
			from: model.KeyLifeCyclePreActivation,
			validTransitions: map[model.KeyLifeCycleState]struct{}{
				model.KeyLifeCycleDestroyed:   {},
				model.KeyLifeCycleActive:      {},
				model.KeyLifeCycleCompromised: {},
			},
		},
		{
			from: model.KeyLifeCycleActive,
			validTransitions: map[model.KeyLifeCycleState]struct{}{
				model.KeyLifeCycleDestroyed:   {},
				model.KeyLifeCycleDeactivated: {},
				model.KeyLifeCycleSuspended:   {},
				model.KeyLifeCycleCompromised: {},
			},
		},
		{
			from: model.KeyLifeCycleSuspended,
			validTransitions: map[model.KeyLifeCycleState]struct{}{
				model.KeyLifeCycleDestroyed:   {},
				model.KeyLifeCycleDeactivated: {},
				model.KeyLifeCycleCompromised: {},
				model.KeyLifeCycleActive:      {},
			},
		},
		{
			from: model.KeyLifeCycleDeactivated,
			validTransitions: map[model.KeyLifeCycleState]struct{}{
				model.KeyLifeCycleDestroyed:   {},
				model.KeyLifeCycleCompromised: {},
			},
		},
		{
			from: model.KeyLifeCycleCompromised,
			validTransitions: map[model.KeyLifeCycleState]struct{}{
				model.KeyLifeCycleDestroyed: {},
			},
		},
		{
			from:             model.KeyLifeCycleDestroyed,
			validTransitions: map[model.KeyLifeCycleState]struct{}{},
		},
		{
			from:             "invalid-state",
			validTransitions: map[model.KeyLifeCycleState]struct{}{},
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
			expResult := make([]model.KeyLifeCycleState, 0, len(tt.validTransitions))
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
		state           model.KeyLifeCycleState
		validOperations spec.KeyUsage
	}{
		{
			state:           model.KeyLifeCyclePreActivation,
			validOperations: spec.KeyUsageNone,
		},
		{
			state:           model.KeyLifeCycleActive,
			validOperations: spec.KeyUsageDecrypt | spec.KeyUsageEncrypt | spec.KeyUsageWrap | spec.KeyUsageUnwrap,
		},
		{
			state:           model.KeyLifeCycleSuspended,
			validOperations: spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		},
		{
			state:           model.KeyLifeCycleDeactivated,
			validOperations: spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		},
		{
			state:           model.KeyLifeCycleCompromised,
			validOperations: spec.KeyUsageDecrypt | spec.KeyUsageUnwrap,
		},
		{
			state:           model.KeyLifeCycleDestroyed,
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
