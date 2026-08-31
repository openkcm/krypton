package keyoperator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

const (
	testTenantID = "tenant-1"
	testKeyID    = "key-1"
)

// stubKeyStore embeds store.Key so tests only need to implement the
// methods they exercise.
type stubKeyStore struct {
	store.Key

	getKeyByID      func(ctx context.Context, id, tenantID string) (*model.Key, error)
	updateKeyStates func(ctx context.Context, q store.UpdateKeyStatesQuery) error
}

func (s *stubKeyStore) GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error) {
	return s.getKeyByID(ctx, id, tenantID)
}

func (s *stubKeyStore) UpdateKeyStates(ctx context.Context, q store.UpdateKeyStatesQuery) error {
	return s.updateKeyStates(ctx, q)
}

func TestUpdateKeyState(t *testing.T) {
	errBoom := errors.New("boom")

	tests := []struct {
		name         string
		updateErr    error
		wantErrIs    []error
		wantErrIsNot []error
		wantNil      bool
	}{
		{
			name:      "success",
			updateErr: nil,
			wantNil:   true,
		},
		{
			name:         "CAS mismatch",
			updateErr:    store.ErrKeyNotFound,
			wantErrIs:    []error{keyoperator.ErrKeyTransitionRejected, store.ErrKeyNotFound},
			wantErrIsNot: []error{keyoperator.ErrUpdateKeyState},
		},
		{
			name:         "generic store error",
			updateErr:    errBoom,
			wantErrIs:    []error{keyoperator.ErrUpdateKeyState, errBoom},
			wantErrIsNot: []error{keyoperator.ErrKeyTransitionRejected},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := &stubKeyStore{
				updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
					return tc.updateErr
				},
			}
			step := keyoperator.UpdateKeyState(testTenantID, testKeyID, keyoperator.Transition{
				FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
				ToLifeCycle:    model.KeyLifeCycleActive,
				FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingCompleted},
				ToProcessing:   model.KeyProcessingInProgress,
			})
			err := step(t.Context(), store.Stores{Keys: keys})

			if tc.wantNil {
				assert.NoError(t, err)
				return
			}
			if !assert.Error(t, err) {
				return
			}
			for _, s := range tc.wantErrIs {
				assert.ErrorIs(t, err, s)
			}
			for _, s := range tc.wantErrIsNot {
				assert.NotErrorIs(t, err, s, "unexpected: err matches %v", s)
			}
		})
	}
}
