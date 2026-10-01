package announcekey

import (
	"context"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// NewSharedState creates a new instance of sharedState.
var NewSharedState = newSharedState

// UpdateKeyState updates the state of the key processing.
func (h *TaskHandler) UpdateKeyState(ctx context.Context, state *sharedState, stores store.Stores, key model.Key) error {
	return h.updateKeyState(ctx, state, stores, key)
}

// State returns the current state of the key processing.
func (s *sharedState) State() model.KeyProcessingStatus {
	return s.state
}

// ErrorMessage returns the error message associated with the key processing, if any.
func (s *sharedState) ErrorMessage() string {
	return s.errMsg
}
