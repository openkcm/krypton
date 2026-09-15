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

	createKey       func(ctx context.Context, key model.Key) error
	getKeyByID      func(ctx context.Context, id, tenantID string) (*model.Key, error)
	updateKeyStates func(ctx context.Context, q store.UpdateKeyStatesQuery) error
}

func (s *stubKeyStore) CreateKey(ctx context.Context, key model.Key) error {
	return s.createKey(ctx, key)
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

func TestUpsertKey(t *testing.T) {
	errBoom := errors.New("boom")

	parentID := "parent-1"
	otherParent := "other-parent"

	newKey := model.Key{
		ID:                 testKeyID,
		Name:               "some-name",
		TenantID:           testTenantID,
		Kind:               "K1",
		ParentID:           &parentID,
		ManagedBy:          "agent-aws",
		LifeCycleState:     model.KeyLifeCyclePreActivation,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
	}

	tests := []struct {
		name string

		createErr error
		existing  *model.Key
		getKeyErr error
		updateErr error

		wantErrIs    []error
		wantErrIsNot []error
		wantNil      bool
	}{
		{
			name:         "generic store error on insert",
			createErr:    errBoom,
			wantErrIs:    []error{keyoperator.ErrCreateKey, errBoom},
			wantErrIsNot: []error{keyoperator.ErrKeyConflict, store.ErrKeyInsertConflict},
		},
		{
			name:      "conflict then GetKeyByID fails",
			createErr: store.ErrKeyInsertConflict,
			getKeyErr: errBoom,
			wantErrIs: []error{keyoperator.ErrGetKey, errBoom},
		},
		{
			name:      "conflict with different name",
			createErr: store.ErrKeyInsertConflict,
			existing: &model.Key{
				ID:                 testKeyID,
				Name:               "different-name",
				TenantID:           testTenantID,
				Kind:               "K1",
				ParentID:           &parentID,
				ManagedBy:          "agent-aws",
				LifeCycleState:     model.KeyLifeCyclePreActivation,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
			},
			wantErrIs: []error{keyoperator.ErrKeyConflict},
		},
		{
			name:      "conflict with different managed_by",
			createErr: store.ErrKeyInsertConflict,
			existing: &model.Key{
				ID:                 testKeyID,
				Name:               "some-name",
				TenantID:           testTenantID,
				Kind:               "K1",
				ParentID:           &parentID,
				ManagedBy:          "other-agent",
				LifeCycleState:     model.KeyLifeCyclePreActivation,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
			},
			wantErrIs: []error{keyoperator.ErrKeyConflict},
		},
		{
			name:      "conflict with different parent_id",
			createErr: store.ErrKeyInsertConflict,
			existing: &model.Key{
				ID:                 testKeyID,
				Name:               "some-name",
				TenantID:           testTenantID,
				Kind:               "K1",
				ParentID:           &otherParent,
				ManagedBy:          "agent-aws",
				LifeCycleState:     model.KeyLifeCyclePreActivation,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
			},
			wantErrIs: []error{keyoperator.ErrKeyConflict},
		},
		{
			name:      "conflict same identity then update store error",
			createErr: store.ErrKeyInsertConflict,
			existing: &model.Key{
				ID:                 testKeyID,
				Name:               "some-name",
				TenantID:           testTenantID,
				Kind:               "K1",
				ParentID:           &parentID,
				ManagedBy:          "agent-aws",
				LifeCycleState:     model.KeyLifeCyclePreActivation,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
			},
			updateErr:    errBoom,
			wantErrIs:    []error{keyoperator.ErrUpdateKeyState, errBoom},
			wantErrIsNot: []error{keyoperator.ErrKeyTransitionRejected},
		},
		{
			name:      "happy path insert succeeds",
			createErr: nil,
			wantNil:   true,
		},
		{
			name:      "conflict same identity CAS updates row",
			createErr: store.ErrKeyInsertConflict,
			existing: &model.Key{
				ID:                 testKeyID,
				Name:               "some-name",
				TenantID:           testTenantID,
				Kind:               "K1",
				ParentID:           &parentID,
				ManagedBy:          "agent-aws",
				LifeCycleState:     model.KeyLifeCyclePreActivation,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
			},
			updateErr: nil,
			wantNil:   true,
		},
		{
			name:      "conflict same identity idempotent replay (CAS matched zero rows)",
			createErr: store.ErrKeyInsertConflict,
			existing: &model.Key{
				ID:                 testKeyID,
				Name:               "some-name",
				TenantID:           testTenantID,
				Kind:               "K1",
				ParentID:           &parentID,
				ManagedBy:          "agent-aws",
				LifeCycleState:     model.KeyLifeCyclePreActivation,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
			},
			updateErr: store.ErrKeyNotFound,
			wantNil:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := &stubKeyStore{
				createKey: func(_ context.Context, _ model.Key) error {
					return tc.createErr
				},
				getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
					if tc.getKeyErr != nil {
						return nil, tc.getKeyErr
					}
					return tc.existing, nil
				},
				updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
					return tc.updateErr
				},
			}

			step := keyoperator.UpsertKey(newKey)
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
