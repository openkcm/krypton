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

	createKey         func(ctx context.Context, key model.Key) error
	getKeyByID        func(ctx context.Context, id, tenantID string) (*model.Key, error)
	getKeyByName      func(ctx context.Context, q store.GetKeyByNameQuery) (*model.Key, error)
	updateKeyStates   func(ctx context.Context, q store.UpdateKeyStatesQuery) error
	getDescendantKeys func(ctx context.Context, q store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error)
}

func (s *stubKeyStore) CreateKey(ctx context.Context, key model.Key) error {
	return s.createKey(ctx, key)
}

func (s *stubKeyStore) GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error) {
	return s.getKeyByID(ctx, id, tenantID)
}

func (s *stubKeyStore) GetKeyByName(ctx context.Context, q store.GetKeyByNameQuery) (*model.Key, error) {
	return s.getKeyByName(ctx, q)
}

func (s *stubKeyStore) UpdateKeyStates(ctx context.Context, q store.UpdateKeyStatesQuery) error {
	return s.updateKeyStates(ctx, q)
}

func (s *stubKeyStore) GetDescendantKeys(ctx context.Context, q store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
	return s.getDescendantKeys(ctx, q)
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

func TestUpsertKey_NilKey(t *testing.T) {
	step := keyoperator.UpsertKey(nil)
	err := step(t.Context(), store.Stores{Keys: &stubKeyStore{}})

	assert.Error(t, err)
	assert.ErrorIs(t, err, keyoperator.ErrNilKey)
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
			name:      "conflict then GetKeyByName fails",
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
				getKeyByName: func(_ context.Context, _ store.GetKeyByNameQuery) (*model.Key, error) {
					if tc.getKeyErr != nil {
						return nil, tc.getKeyErr
					}
					return tc.existing, nil
				},
				updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
					return tc.updateErr
				},
			}

			step := keyoperator.UpsertKey(&newKey)
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

func TestUpsertKey_CASUsesExistingProcessingStatus(t *testing.T) {
	parentID := "parent-1"

	tests := []struct {
		name           string
		existingStatus model.KeyProcessingStatus
		existingState  model.KeyLifeCycleState
	}{
		{
			name:           "existing key in pending status",
			existingStatus: model.KeyProcessingPending,
			existingState:  model.KeyLifeCycleActive,
		},
		{
			name:           "existing key in in-progress status",
			existingStatus: model.KeyProcessingInProgress,
			existingState:  model.KeyLifeCycleActive,
		},
		{
			name:           "existing key in completed status",
			existingStatus: model.KeyProcessingCompleted,
			existingState:  model.KeyLifeCycleSuspended,
		},
		{
			name:           "existing key in failed status",
			existingStatus: model.KeyProcessingFailed,
			existingState:  model.KeyLifeCycleDeactivated,
		},
		{
			name:           "existing key in preactive status",
			existingStatus: model.KeyProcessingFailed,
			existingState:  model.KeyLifeCyclePreActivation,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
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

			existing := &model.Key{
				ID:                 "existing-key-id",
				Name:               "some-name",
				TenantID:           testTenantID,
				Kind:               "K1",
				ParentID:           &parentID,
				ManagedBy:          "agent-aws",
				LifeCycleState:     tc.existingState,
				KeyProcessingState: model.KeyProcessingState{Status: tc.existingStatus},
			}

			var capturedQuery store.UpdateKeyStatesQuery
			keys := &stubKeyStore{
				createKey: func(_ context.Context, _ model.Key) error {
					return store.ErrKeyInsertConflict
				},
				getKeyByName: func(_ context.Context, _ store.GetKeyByNameQuery) (*model.Key, error) {
					return existing, nil
				},
				updateKeyStates: func(_ context.Context, q store.UpdateKeyStatesQuery) error {
					capturedQuery = q
					return nil
				},
			}

			step := keyoperator.UpsertKey(&newKey)
			err := step(t.Context(), store.Stores{Keys: keys})

			assert.NoError(t, err)
			assert.Equal(t, existing.ID, capturedQuery.ID)
			assert.Equal(t, existing.TenantID, capturedQuery.TenantID)
			assert.Equal(t, newKey.LifeCycleState, capturedQuery.ToState)
			assert.Equal(t, newKey.KeyProcessingState.Status, capturedQuery.ToStatus)
			assert.Equal(t, []model.KeyLifeCycleState{tc.existingState}, capturedQuery.FromState)
			assert.Equal(t, []model.KeyProcessingStatus{tc.existingStatus}, capturedQuery.FromStatus)
		})
	}
}
