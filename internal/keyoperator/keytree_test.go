package keyoperator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/handler/activatekey"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// stubPreparer is a no-op JobGroupPreparer that returns the group as-is.
type stubPreparer struct{}

func (*stubPreparer) PrepareJobGroup(_ context.Context, group orbital.JobGroup) (orbital.JobGroup, error) {
	return group, nil
}

// activateSelector is the standard selector used by the activate-key action.
var activateSelector = keyoperator.AnySelectorMatches(
	keyoperator.SelectByKeyStates(model.KeyLifeCycleActive, model.KeyProcessingFailed),
	keyoperator.SelectByKeyStates(model.KeyLifeCycleSuspended, model.KeyProcessingCompleted),
	keyoperator.SelectByKeyStates(model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted),
)

func TestApplyKeyAction(t *testing.T) {
	t.Run("fetch keytree error", func(t *testing.T) {
		errStore := errors.New("store failure")

		tests := []struct {
			name      string
			cascading bool
			keyStore  *stubKeyStore
		}{
			{
				name:      "cascading: GetDescendantKeys returns error",
				cascading: true,
				keyStore: &stubKeyStore{
					getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
						return store.GetDescendantKeysResult{}, errStore
					},
				},
			},
			{
				name:      "non-cascading: GetKeyByID returns error",
				cascading: false,
				keyStore: &stubKeyStore{
					getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
						return nil, errStore
					},
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := keyoperator.ApplyKeyAction(
					t.Context(),
					store.Stores{Keys: tc.keyStore},
					&stubPreparer{},
					keyoperator.ApplyKeyActionRequest{
						TenantID:     testTenantID,
						KeyID:        testKeyID,
						ToState:      model.KeyLifeCycleActive,
						Selector:     activateSelector,
						Cascading:    tc.cascading,
						JobType:      activatekey.JobType,
						JobGroupType: activatekey.JobGroupType,
					},
				)

				assert.Empty(t, got)
				assert.ErrorIs(t, err, errStore)
			})
		}
	})

	t.Run("no actionable keys", func(t *testing.T) {
		tests := []struct {
			name string
			key  model.Key
		}{
			{
				name: "non-transitionable: destroyed has no outgoing transitions",
				key: model.Key{
					ID:                 testKeyID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCycleDestroyed,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				},
			},
			{
				name: "non-transitionable: deactivated cannot transition to active",
				key: model.Key{
					ID:                 testKeyID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCycleDeactivated,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				},
			},
			{
				name: "selector mismatch: pre-activation with pending processing",
				key: model.Key{
					ID:                 testKeyID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCyclePreActivation,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
				},
			},
			{
				name: "selector mismatch: active with in-progress processing",
				key: model.Key{
					ID:                 testKeyID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCycleActive,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingInProgress},
				},
			},
			{
				name: "already at target state with completed processing",
				key: model.Key{
					ID:                 testKeyID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCycleActive,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				},
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				keyStore := &stubKeyStore{
					getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
						return &tc.key, nil
					},
				}

				got, err := keyoperator.ApplyKeyAction(
					t.Context(),
					store.Stores{Keys: keyStore},
					&stubPreparer{},
					keyoperator.ApplyKeyActionRequest{
						TenantID:     testTenantID,
						KeyID:        testKeyID,
						ToState:      model.KeyLifeCycleActive,
						Selector:     activateSelector,
						JobType:      activatekey.JobType,
						JobGroupType: activatekey.JobGroupType,
					},
				)

				assert.Empty(t, got)
				assert.ErrorIs(t, err, keyoperator.ErrNoKeysFound)
			})
		}
	})

	// ── excluded branch (cascading) ─────────────────────────────────────
	//
	// Base tree used by the first two cases:
	//
	//        root (pre-activation, completed)  ← activatable
	//        /                              \
	//  child-B (deactivated, completed)   child-A (pre-activation, completed)
	//   [NOT activatable]                    [activatable]
	//
	// child-B is placed before child-A so the exclusion is recorded first.

	t.Run("excluded branch", func(t *testing.T) {
		rootID := "root-key"
		childAID := "child-A"
		childBID := "child-B"

		twoLayerTree := model.KeyTree{
			{
				{
					ID:                 rootID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCyclePreActivation,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				},
			},
			{
				{
					ID:                 childBID,
					TenantID:           testTenantID,
					ParentID:           &rootID,
					LifeCycleState:     model.KeyLifeCycleDeactivated,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				},
				{
					ID:                 childAID,
					TenantID:           testTenantID,
					ParentID:           &rootID,
					LifeCycleState:     model.KeyLifeCyclePreActivation,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				},
			},
		}

		tests := []struct {
			name         string
			keyTree      model.KeyTree
			allowPartial bool
			wantErr      error
			wantJobKeys  [][]string // expected key IDs per job, in order
		}{
			{
				name:         "AllowPartial false rejects when any key is excluded",
				keyTree:      twoLayerTree,
				allowPartial: false,
				wantErr:      keyoperator.ErrNoKeysFound,
			},
			{
				name:         "AllowPartial true activates valid branch only",
				keyTree:      twoLayerTree,
				allowPartial: true,
				wantJobKeys:  [][]string{{rootID}, {childAID}}, // layer 0 (root) + layer 1 (child-A)
			},
			{
				name: "parent exclusion cascades to children",
				keyTree: model.KeyTree{
					{
						{
							ID:                 rootID,
							TenantID:           testTenantID,
							LifeCycleState:     model.KeyLifeCycleDeactivated,
							KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
						},
					},
					{
						{
							ID:                 childAID,
							TenantID:           testTenantID,
							ParentID:           &rootID,
							LifeCycleState:     model.KeyLifeCyclePreActivation,
							KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
						},
					},
				},
				allowPartial: true,
				wantErr:      keyoperator.ErrNoKeysFound,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				keyStore := &stubKeyStore{
					getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
						return store.GetDescendantKeysResult{KeyTree: tc.keyTree}, nil
					},
					updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
						return nil
					},
				}

				got, err := keyoperator.ApplyKeyAction(
					t.Context(),
					store.Stores{Keys: keyStore},
					&stubPreparer{},
					keyoperator.ApplyKeyActionRequest{
						TenantID:     testTenantID,
						KeyID:        rootID,
						ToState:      model.KeyLifeCycleActive,
						Selector:     activateSelector,
						Cascading:    true,
						AllowPartial: tc.allowPartial,
						JobType:      activatekey.JobType,
						JobGroupType: activatekey.JobGroupType,
					},
				)

				if tc.wantErr != nil {
					assert.Empty(t, got)
					assert.ErrorIs(t, err, tc.wantErr)
					return
				}

				require.NoError(t, err)
				assert.Equal(t, activatekey.JobGroupType, got.Type)
				require.Len(t, got.Jobs, len(tc.wantJobKeys))
				for i, job := range got.Jobs {
					assert.Equal(t, activatekey.JobType, job.Type)
					assertJobDataContainsKeys(t, job.Data, tc.wantJobKeys[i]...)
				}
			})
		}
	})

	// ── selector ordering: already-completed parent must be skipped ─────
	t.Run("already-completed parent is skipped not excluded even if selector omits target state", func(t *testing.T) {
		// Narrow selector that intentionally does NOT include (Active, Completed).
		// This exposes a bug if the selector runs before the already-completed
		// skip: the root would be excluded instead of skipped, cascading to
		// all children.
		narrowSelector := keyoperator.AnySelectorMatches(
			keyoperator.SelectByKeyStates(
				model.KeyLifeCyclePreActivation,
				model.KeyProcessingCompleted,
			),
		)

		rootID := "root-key"
		childID := "child-key"

		keyStore := &stubKeyStore{
			getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
				return store.GetDescendantKeysResult{
					KeyTree: model.KeyTree{
						// Layer 0: root already at target state (Active + Completed)
						{
							{
								ID:                 rootID,
								TenantID:           testTenantID,
								LifeCycleState:     model.KeyLifeCycleActive,
								KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
							},
						},
						// Layer 1: child in PreActivation + Completed (activatable)
						{
							{
								ID:                 childID,
								TenantID:           testTenantID,
								ParentID:           &rootID,
								LifeCycleState:     model.KeyLifeCyclePreActivation,
								KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
							},
						},
					},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
				return nil
			},
		}

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     testTenantID,
				KeyID:        rootID,
				ToState:      model.KeyLifeCycleActive,
				Selector:     narrowSelector,
				Cascading:    true,
				AllowPartial: true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		// Root should be SKIPPED (not excluded), child should be activated.
		require.NoError(t, err)
		assert.Equal(t, activatekey.JobGroupType, got.Type)
		require.Len(t, got.Jobs, 1)
		assert.Equal(t, activatekey.JobType, got.Jobs[0].Type)
		assertJobDataContainsKeys(t, got.Jobs[0].Data, childID)
	})

	// ── UpdateKeyState error ────────────────────────────────────────────
	t.Run("UpdateKeyState error propagates", func(t *testing.T) {
		errUpdate := errors.New("update failed")

		keyStore := &stubKeyStore{
			getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
				return &model.Key{
					ID:                 testKeyID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCyclePreActivation,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
				return errUpdate
			},
		}

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     testTenantID,
				KeyID:        testKeyID,
				ToState:      model.KeyLifeCycleActive,
				Selector:     activateSelector,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		assert.Empty(t, got)
		assert.ErrorIs(t, err, errUpdate)
	})

	// ── PrepareJobGroup error ───────────────────────────────────────────
	t.Run("PrepareJobGroup error propagates", func(t *testing.T) {
		errPrepare := errors.New("prepare failed")

		keyStore := &stubKeyStore{
			getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
				return &model.Key{
					ID:                 testKeyID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCyclePreActivation,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
				return nil
			},
		}

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&failPreparer{err: errPrepare},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     testTenantID,
				KeyID:        testKeyID,
				ToState:      model.KeyLifeCycleActive,
				Selector:     activateSelector,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		assert.Empty(t, got)
		assert.ErrorIs(t, err, errPrepare)
	})

	// ── success ─────────────────────────────────────────────────────────
	t.Run("success", func(t *testing.T) {
		rootID := "root-key"
		childID := "child-key"

		tests := []struct {
			name        string
			action      keyoperator.ApplyKeyActionRequest
			keyStore    *stubKeyStore
			wantJobKeys [][]string // expected key IDs per job, in order
		}{
			{
				name: "non-cascading: pre-activation to active",
				action: keyoperator.ApplyKeyActionRequest{
					TenantID:     testTenantID,
					KeyID:        testKeyID,
					ToState:      model.KeyLifeCycleActive,
					Selector:     activateSelector,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
				keyStore: &stubKeyStore{
					getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
						return &model.Key{
							ID:                 testKeyID,
							TenantID:           testTenantID,
							LifeCycleState:     model.KeyLifeCyclePreActivation,
							KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
						}, nil
					},
					updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
						return nil
					},
				},
				wantJobKeys: [][]string{{testKeyID}},
			},
			{
				name: "non-cascading: suspended to active (re-activation)",
				action: keyoperator.ApplyKeyActionRequest{
					TenantID:     testTenantID,
					KeyID:        testKeyID,
					ToState:      model.KeyLifeCycleActive,
					Selector:     activateSelector,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
				keyStore: &stubKeyStore{
					getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
						return &model.Key{
							ID:                 testKeyID,
							TenantID:           testTenantID,
							LifeCycleState:     model.KeyLifeCycleSuspended,
							KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
						}, nil
					},
					updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
						return nil
					},
				},
				wantJobKeys: [][]string{{testKeyID}},
			},
			{
				name: "non-cascading: active key with failed processing is retried",
				action: keyoperator.ApplyKeyActionRequest{
					TenantID:     testTenantID,
					KeyID:        testKeyID,
					ToState:      model.KeyLifeCycleActive,
					Selector:     activateSelector,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
				keyStore: &stubKeyStore{
					getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
						return &model.Key{
							ID:                 testKeyID,
							TenantID:           testTenantID,
							LifeCycleState:     model.KeyLifeCycleActive,
							KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingFailed},
						}, nil
					},
					updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
						return nil
					},
				},
				wantJobKeys: [][]string{{testKeyID}},
			},
			{
				name: "cascading: multi-layer tree fully activated",
				action: keyoperator.ApplyKeyActionRequest{
					TenantID:     testTenantID,
					KeyID:        rootID,
					ToState:      model.KeyLifeCycleActive,
					Selector:     activateSelector,
					Cascading:    true,
					AllowPartial: false,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
				keyStore: &stubKeyStore{
					getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
						return store.GetDescendantKeysResult{
							KeyTree: model.KeyTree{
								{
									{
										ID:                 rootID,
										TenantID:           testTenantID,
										LifeCycleState:     model.KeyLifeCyclePreActivation,
										KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
									},
								},
								{
									{
										ID:                 childID,
										TenantID:           testTenantID,
										ParentID:           &rootID,
										LifeCycleState:     model.KeyLifeCyclePreActivation,
										KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
									},
								},
							},
						}, nil
					},
					updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
						return nil
					},
				},
				wantJobKeys: [][]string{{rootID}, {childID}}, // one job per layer
			},
			{
				name: "cascading: already-completed root skipped, child still activated",
				action: keyoperator.ApplyKeyActionRequest{
					TenantID:     testTenantID,
					KeyID:        rootID,
					ToState:      model.KeyLifeCycleActive,
					Selector:     activateSelector,
					Cascading:    true,
					AllowPartial: false,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
				keyStore: &stubKeyStore{
					getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
						return store.GetDescendantKeysResult{
							KeyTree: model.KeyTree{
								{
									{
										ID:                 rootID,
										TenantID:           testTenantID,
										LifeCycleState:     model.KeyLifeCycleActive,
										KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
									},
								},
								{
									{
										ID:                 childID,
										TenantID:           testTenantID,
										ParentID:           &rootID,
										LifeCycleState:     model.KeyLifeCyclePreActivation,
										KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
									},
								},
							},
						}, nil
					},
					updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
						return nil
					},
				},
				wantJobKeys: [][]string{{childID}}, // only child layer; root is skipped (not excluded)
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := keyoperator.ApplyKeyAction(
					t.Context(),
					store.Stores{Keys: tc.keyStore},
					&stubPreparer{},
					tc.action,
				)

				require.NoError(t, err)
				assert.Equal(t, activatekey.JobGroupType, got.Type)
				require.Len(t, got.Jobs, len(tc.wantJobKeys))
				for i, job := range got.Jobs {
					assert.Equal(t, activatekey.JobType, job.Type)
					assertJobDataContainsKeys(t, job.Data, tc.wantJobKeys[i]...)
				}
			})
		}
	})
}

// failPreparer is a JobGroupPreparer that always returns an error.
type failPreparer struct {
	err error
}

func (f *failPreparer) PrepareJobGroup(_ context.Context, _ orbital.JobGroup) (orbital.JobGroup, error) {
	return orbital.JobGroup{}, f.err
}

func assertJobDataContainsKeys(t *testing.T, jobData []byte, expectedKeyIDs ...string) {
	t.Helper()
	var layer handler.KeyLayer
	require.NoError(t, json.Unmarshal(jobData, &layer))
	actualIDs := make([]string, 0, len(layer.Identifiers))
	for _, ki := range layer.Identifiers {
		actualIDs = append(actualIDs, ki.ID)
	}
	assert.ElementsMatch(t, expectedKeyIDs, actualIDs)
}
