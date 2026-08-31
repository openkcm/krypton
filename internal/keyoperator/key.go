// Package keyoperator provides transaction-scoped operations for keys and
// key versions. Each constructor returns a store.TransactionFunc that can
// be composed into a store.ChainTransaction.
package keyoperator

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// Transition holds the state transition inputs for UpdateKeyState.
type Transition struct {
	FromLifeCycle  []model.KeyLifeCycleState
	ToLifeCycle    model.KeyLifeCycleState
	FromProcessing []model.KeyProcessingStatus
	ToProcessing   model.KeyProcessingStatus
}

// Class sentinels raised by key-level operations. The transport layer
// switches on these via errors.Is to map to gRPC status + proto detail
// codes.
var (
	// ErrKeyTransitionRejected signals that the compare-and-set update
	// did not match: the key's current state does not match the expected
	// states.
	ErrKeyTransitionRejected = errors.New("cannot transition key: current state does not match the expected states")

	// ErrUpdateKeyState signals a failed key state update.
	ErrUpdateKeyState = errors.New("failed to update key life cycle and processing state")

	// ErrGetKey signals a failed read of the target key.
	ErrGetKey = errors.New("failed to get key")
)

// UpdateKeyState returns a transaction step that transitions the key's
// life cycle and processing status.
func UpdateKeyState(tenantID, keyID string, transition Transition) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		err := stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:         keyID,
			TenantID:   tenantID,
			FromState:  transition.FromLifeCycle,
			ToState:    transition.ToLifeCycle,
			FromStatus: transition.FromProcessing,
			ToStatus:   transition.ToProcessing,
		})
		if err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				return fmt.Errorf("%w: %w", ErrKeyTransitionRejected, err)
			}
			return fmt.Errorf("%w: %w", ErrUpdateKeyState, err)
		}
		return nil
	}
}
