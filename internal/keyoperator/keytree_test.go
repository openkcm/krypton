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
				name: "invalid transition: destroyed has no outgoing transitions",
				key: model.Key{
					ID:                 testKeyID,
					TenantID:           testTenantID,
					LifeCycleState:     model.KeyLifeCycleDestroyed,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
				},
			},
			{
				name: "invalid transition: deactivated cannot transition to active",
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
					assertJobDataTenantID(t, job.Data, testTenantID)
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
		assertJobDataTenantID(t, got.Jobs[0].Data, testTenantID)
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
					assertJobDataTenantID(t, job.Data, testTenantID)
				}
			})
		}
	})
}

// ── cascading multi-layer: all keys included ────────────────────────────
func TestApplyKeyAction_CascadingMultiLayerAllIncluded(t *testing.T) {
	t.Run("wide tree: two branches across 3 layers with mixed activatable states", func(t *testing.T) {
		// given — all keys can transition to active, mixed pre-activation and suspended.
		//
		//                 root (pre-activation + completed)
		//                /                                 \
		//   child-A (pre-activation + completed)   child-B (suspended + completed)
		//        |                                       |
		//   grand-A (pre-activation + completed)   grand-B (pre-activation + completed)
		rootID := "root"
		childAID := "child-A"
		childBID := "child-B"
		grandAID := "grand-A"
		grandBID := "grand-B"

		keyStore := &stubKeyStore{
			getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
				return store.GetDescendantKeysResult{
					KeyTree: model.KeyTree{
						{
							{
								ID: rootID, TenantID: testTenantID,
								LifeCycleState:     model.KeyLifeCyclePreActivation,
								KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
							},
						},
						{
							{
								ID: childAID, TenantID: testTenantID, ParentID: &rootID,
								LifeCycleState:     model.KeyLifeCyclePreActivation,
								KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
							},
							{
								ID: childBID, TenantID: testTenantID, ParentID: &rootID,
								LifeCycleState:     model.KeyLifeCycleSuspended,
								KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
							},
						},
						{
							{
								ID: grandAID, TenantID: testTenantID, ParentID: &childAID,
								LifeCycleState:     model.KeyLifeCyclePreActivation,
								KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
							},
							{
								ID: grandBID, TenantID: testTenantID, ParentID: &childBID,
								LifeCycleState:     model.KeyLifeCyclePreActivation,
								KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
							},
						},
					},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error { return nil },
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
				AllowPartial: true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		require.NoError(t, err)
		assert.Equal(t, activatekey.JobGroupType, got.Type)
		require.Len(t, got.Jobs, 3, "one job per layer")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, rootID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childAID, childBID)
		assertJobDataContainsKeys(t, got.Jobs[2].Data, grandAID, grandBID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, testTenantID)
		}
	})

	t.Run("deep tree: 4 layers single chain all activatable", func(t *testing.T) {
		// given — linear chain, each layer has exactly one key.
		//
		//   root (pre-activation + completed)
		//     └── child (suspended + completed)
		//           └── grand (pre-activation + completed)
		//                 └── great (pre-activation + completed)
		rootID := "root"
		childID := "child"
		grandID := "grand"
		greatID := "great"

		keyStore := &stubKeyStore{
			getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
				return store.GetDescendantKeysResult{
					KeyTree: model.KeyTree{
						{{ID: rootID, TenantID: testTenantID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}}},
						{{ID: childID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCycleSuspended, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}}},
						{{ID: grandID, TenantID: testTenantID, ParentID: &childID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}}},
						{{ID: greatID, TenantID: testTenantID, ParentID: &grandID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}}},
					},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error { return nil },
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
				AllowPartial: true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		require.NoError(t, err)
		require.Len(t, got.Jobs, 4, "one job per layer")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, rootID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childID)
		assertJobDataContainsKeys(t, got.Jobs[2].Data, grandID)
		assertJobDataContainsKeys(t, got.Jobs[3].Data, greatID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, testTenantID)
		}
	})

	t.Run("wide and deep tree: 4 layers with fan-out all activatable", func(t *testing.T) {
		// given — wide + deep tree, every key can transition to active.
		//
		//                         root (pre-activation + completed)
		//                        /                                  \
		//       child-A (pre-activation + completed)         child-B (suspended + completed)
		//          /                    \                          |
		//   grand-A1 (pre-act + comp)  grand-A2 (suspended + comp)  grand-B1 (pre-act + comp)
		//        |
		//   great-A1 (pre-act + comp)
		rootID := "root"
		childAID := "child-A"
		childBID := "child-B"
		grandA1ID := "grand-A1"
		grandA2ID := "grand-A2"
		grandB1ID := "grand-B1"
		greatA1ID := "great-A1"

		keyStore := &stubKeyStore{
			getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
				return store.GetDescendantKeysResult{
					KeyTree: model.KeyTree{
						{
							{ID: rootID, TenantID: testTenantID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
						{
							{ID: childAID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: childBID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCycleSuspended, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
						{
							{ID: grandA1ID, TenantID: testTenantID, ParentID: &childAID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: grandA2ID, TenantID: testTenantID, ParentID: &childAID, LifeCycleState: model.KeyLifeCycleSuspended, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: grandB1ID, TenantID: testTenantID, ParentID: &childBID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
						{
							{ID: greatA1ID, TenantID: testTenantID, ParentID: &grandA1ID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
					},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error { return nil },
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
				AllowPartial: true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		require.NoError(t, err)
		require.Len(t, got.Jobs, 4, "one job per layer")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, rootID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childAID, childBID)
		assertJobDataContainsKeys(t, got.Jobs[2].Data, grandA1ID, grandA2ID, grandB1ID)
		assertJobDataContainsKeys(t, got.Jobs[3].Data, greatA1ID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, testTenantID)
		}
	})

	t.Run("wide and deep tree: destroyed grandchild excluded, rest activated", func(t *testing.T) {
		// given — same shape as above but child-B is pre-activation + completed
		// and grand-A1 is destroyed + completed (cannot transition to active).
		// grand-A1 is excluded; its child great-A1 is cascade-excluded too.
		//
		//                         root (pre-activation + completed)
		//                        /                                  \
		//       child-A (pre-activation + completed)         child-B (pre-activation + completed)
		//          /                    \                          |
		//   grand-A1 (destroyed + comp)  grand-A2 (suspended + comp)  grand-B1 (pre-act + comp)
		//        |
		//   great-A1 (pre-act + comp) ← cascade-excluded (parent grand-A1 excluded)
		rootID := "root"
		childAID := "child-A"
		childBID := "child-B"
		grandA1ID := "grand-A1"
		grandA2ID := "grand-A2"
		grandB1ID := "grand-B1"
		greatA1ID := "great-A1"

		keyStore := &stubKeyStore{
			getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
				return store.GetDescendantKeysResult{
					KeyTree: model.KeyTree{
						{
							{ID: rootID, TenantID: testTenantID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
						{
							{ID: childAID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: childBID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
						{
							{ID: grandA1ID, TenantID: testTenantID, ParentID: &childAID, LifeCycleState: model.KeyLifeCycleDestroyed, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: grandA2ID, TenantID: testTenantID, ParentID: &childAID, LifeCycleState: model.KeyLifeCycleSuspended, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: grandB1ID, TenantID: testTenantID, ParentID: &childBID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
						{
							{ID: greatA1ID, TenantID: testTenantID, ParentID: &grandA1ID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
					},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error { return nil },
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
				AllowPartial: true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		// grand-A1 excluded (destroyed), great-A1 cascade-excluded (parent excluded)
		// remaining 5 keys: root, child-A, child-B, grand-A2, grand-B1
		require.NoError(t, err)
		require.Len(t, got.Jobs, 3, "3 jobs: layers 0, 1, 2 (layer 3 all excluded)")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, rootID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childAID, childBID)
		assertJobDataContainsKeys(t, got.Jobs[2].Data, grandA2ID, grandB1ID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, testTenantID)
		}
	})

	t.Run("already-completed root skipped, both branches still fully activated", func(t *testing.T) {
		// given — root already at target state, two child branches both activatable.
		//
		//              root (active + completed) ← skipped
		//             /                           \
		//   child-A (pre-act + comp)        child-B (pre-act + comp)
		//        |                                |
		//   grand-A (pre-act + comp)        grand-B (suspended + comp)
		rootID := "root"
		childAID := "child-A"
		childBID := "child-B"
		grandAID := "grand-A"
		grandBID := "grand-B"

		keyStore := &stubKeyStore{
			getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
				return store.GetDescendantKeysResult{
					KeyTree: model.KeyTree{
						{
							{ID: rootID, TenantID: testTenantID, LifeCycleState: model.KeyLifeCycleActive, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
						{
							{ID: childAID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: childBID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
						{
							{ID: grandAID, TenantID: testTenantID, ParentID: &childAID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: grandBID, TenantID: testTenantID, ParentID: &childBID, LifeCycleState: model.KeyLifeCycleSuspended, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
					},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error { return nil },
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
				AllowPartial: true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		// root is skipped (already active + completed), but children and grandchildren are activated
		require.NoError(t, err)
		require.Len(t, got.Jobs, 2, "two jobs: layer 1 and layer 2 (root layer produces no job)")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, childAID, childBID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, grandAID, grandBID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, testTenantID)
		}
	})

	t.Run("failed processing retry mixed with fresh activation across branches", func(t *testing.T) {
		// given — root has failed processing (retry), children are fresh pre-activation.
		//
		//              root (active + failed) ← retried
		//             /                        \
		//   child-A (pre-act + comp)     child-B (pre-act + comp)
		rootID := "root"
		childAID := "child-A"
		childBID := "child-B"

		keyStore := &stubKeyStore{
			getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
				return store.GetDescendantKeysResult{
					KeyTree: model.KeyTree{
						{
							{ID: rootID, TenantID: testTenantID, LifeCycleState: model.KeyLifeCycleActive, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingFailed}},
						},
						{
							{ID: childAID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
							{ID: childBID, TenantID: testTenantID, ParentID: &rootID, LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
						},
					},
				}, nil
			},
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error { return nil },
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
				AllowPartial: true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		require.NoError(t, err)
		require.Len(t, got.Jobs, 2)
		assertJobDataContainsKeys(t, got.Jobs[0].Data, rootID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childAID, childBID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, testTenantID)
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

// assertJobDataTenantID verifies every identifier in the job data carries the expected tenant ID.
func assertJobDataTenantID(t *testing.T, jobData []byte, expectedTenantID string) {
	t.Helper()
	var layer handler.KeyLayer
	require.NoError(t, json.Unmarshal(jobData, &layer))
	for _, ki := range layer.Identifiers {
		assert.Equal(t, expectedTenantID, ki.TenantID, "key %s has wrong tenant ID", ki.ID)
	}
}
