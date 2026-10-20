package keyoperator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/handler/activatekey"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// activateFilter is the standard filter used by the activate-key action.
var activateFilter = []keyoperator.KeyFilter{
	{
		LifeCycleState: model.KeyLifeCycleActive,
		Status: []model.KeyProcessingStatus{
			model.KeyProcessingFailed,
			model.KeyProcessingCompleted,
		},
	},
	{
		LifeCycleState: model.KeyLifeCycleSuspended,
		Status: []model.KeyProcessingStatus{
			model.KeyProcessingCompleted,
		},
	},
	{
		LifeCycleState: model.KeyLifeCyclePreActivation,
		Status: []model.KeyProcessingStatus{
			model.KeyProcessingCompleted,
		},
	},
}

func TestApplyKeyAction(t *testing.T) {
	db := createDatabase(t)
	tenantID := createTenant(t, db)
	keyStore := storesql.NewKeyStore(db)

	t.Run("fetch keytree error", func(t *testing.T) {
		nonExistentKeyID := uuid.New().String()

		tests := []struct {
			name      string
			cascading bool
		}{
			{
				name:      "cascading: GetDescendantKeys returns error for non-existent key",
				cascading: true,
			},
			{
				name:      "non-cascading: GetKeyByID returns error for non-existent key",
				cascading: false,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				got, err := keyoperator.ApplyKeyAction(
					t.Context(),
					store.Stores{Keys: keyStore},
					&stubPreparer{},
					keyoperator.ApplyKeyActionRequest{
						TenantID:     tenantID,
						KeyID:        nonExistentKeyID,
						ToState:      model.KeyLifeCycleActive,
						KeyFilters:   activateFilter,
						Cascading:    tc.cascading,
						JobType:      activatekey.JobType,
						JobGroupType: activatekey.JobGroupType,
					},
				)

				assert.Empty(t, got)
				assert.ErrorIs(t, err, keyoperator.ErrNoKeysFound)
			})
		}

		// ── non-cascading: key exists but KeyFilter rejects it ──────────
		t.Run("non-cascading: key exists but no filter matches", func(t *testing.T) {
			// The key is pre-activation + completed; each sub-case supplies
			// filters that do not match this combination.
			key := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
				model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

			tests := []struct {
				name       string
				keyFilters []keyoperator.KeyFilter
			}{
				{
					name:       "nil filters",
					keyFilters: nil,
				},
				{
					name:       "empty filters",
					keyFilters: []keyoperator.KeyFilter{},
				},
				{
					name: "lifecycle state mismatch",
					keyFilters: []keyoperator.KeyFilter{
						{
							LifeCycleState: model.KeyLifeCycleActive,
							Status:         []model.KeyProcessingStatus{model.KeyProcessingCompleted},
						},
					},
				},
				{
					name: "processing status mismatch",
					keyFilters: []keyoperator.KeyFilter{
						{
							LifeCycleState: model.KeyLifeCyclePreActivation,
							Status:         []model.KeyProcessingStatus{model.KeyProcessingFailed},
						},
					},
				},
				{
					name: "multiple filters none matching",
					keyFilters: []keyoperator.KeyFilter{
						{
							LifeCycleState: model.KeyLifeCycleActive,
							Status:         []model.KeyProcessingStatus{model.KeyProcessingCompleted},
						},
						{
							LifeCycleState: model.KeyLifeCycleSuspended,
							Status:         []model.KeyProcessingStatus{model.KeyProcessingCompleted},
						},
					},
				},
			}

			for _, tc := range tests {
				t.Run(tc.name, func(t *testing.T) {
					got, err := keyoperator.ApplyKeyAction(
						t.Context(),
						store.Stores{Keys: keyStore},
						&stubPreparer{},
						keyoperator.ApplyKeyActionRequest{
							TenantID:     tenantID,
							KeyID:        key.ID,
							ToState:      model.KeyLifeCycleActive,
							KeyFilters:   tc.keyFilters,
							JobType:      activatekey.JobType,
							JobGroupType: activatekey.JobGroupType,
						},
					)

					assert.Empty(t, got)
					assert.ErrorIs(t, err, keyoperator.ErrNoKeysFound)
				})
			}
		})
	})

	t.Run("no actionable keys", func(t *testing.T) {
		tests := []struct {
			name string
			lcs  model.KeyLifeCycleState
			ps   model.KeyProcessingStatus
		}{
			{
				name: "invalid transition: destroyed has no outgoing transitions",
				lcs:  model.KeyLifeCycleDestroyed,
				ps:   model.KeyProcessingCompleted,
			},
			{
				name: "invalid transition: deactivated cannot transition to active",
				lcs:  model.KeyLifeCycleDeactivated,
				ps:   model.KeyProcessingCompleted,
			},
			{
				name: "filter mismatch: pre-activation with pending processing",
				lcs:  model.KeyLifeCyclePreActivation,
				ps:   model.KeyProcessingPending,
			},
			{
				name: "filter mismatch: active with in-progress processing",
				lcs:  model.KeyLifeCycleActive,
				ps:   model.KeyProcessingInProgress,
			},
			{
				name: "already at target state with completed processing",
				lcs:  model.KeyLifeCycleActive,
				ps:   model.KeyProcessingCompleted,
			},
		}

		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				key := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil, tc.lcs, tc.ps)

				got, err := keyoperator.ApplyKeyAction(
					t.Context(),
					store.Stores{Keys: keyStore},
					&stubPreparer{},
					keyoperator.ApplyKeyActionRequest{
						TenantID:     tenantID,
						KeyID:        key.ID,
						ToState:      model.KeyLifeCycleActive,
						KeyFilters:   activateFilter,
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
	// With a real database, the GetDescendantKeys recursive CTE applies
	// filters inside the query, so non-matching keys and their subtrees
	// are excluded at the SQL level.
	t.Run("excluded branch", func(t *testing.T) {
		t.Run("non-activatable branch filtered by database", func(t *testing.T) {
			// given — child-B is deactivated and gets excluded by the SQL
			// CTE filter; root and child-A are activatable.
			//
			//        root (pre-activation, completed)  ← activatable
			//        /                              \
			//  child-B (deactivated, completed)   child-A (pre-activation, completed)
			//   [filtered by DB]                    [activatable]
			root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
				model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
			childA := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
				model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
			seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
				model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted) // child-B

			got, err := keyoperator.ApplyKeyAction(
				t.Context(),
				store.Stores{Keys: keyStore},
				&stubPreparer{},
				keyoperator.ApplyKeyActionRequest{
					TenantID:     tenantID,
					KeyID:        root.ID,
					ToState:      model.KeyLifeCycleActive,
					KeyFilters:   activateFilter,
					Cascading:    true,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
			)

			require.NoError(t, err)
			assert.Equal(t, activatekey.JobGroupType, got.Type)
			require.Len(t, got.Jobs, 2)
			for _, job := range got.Jobs {
				assert.Equal(t, activatekey.JobType, job.Type)
				assertJobDataTenantID(t, job.Data, tenantID)
			}
			assertJobDataContainsKeys(t, got.Jobs[0].Data, root.ID)
			assertJobDataContainsKeys(t, got.Jobs[1].Data, childA.ID)
		})

		t.Run("root excluded by filter cascades to all children", func(t *testing.T) {
			// given — root is deactivated: the SQL CTE anchor does not
			// match, so the entire subtree is absent from the result.
			//
			//  root (deactivated, completed) ← excluded by filter
			//    \
			//     child-A (pre-activation, completed)  ← cascade-excluded
			root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
				model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
			seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
				model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted) // child-A

			got, err := keyoperator.ApplyKeyAction(
				t.Context(),
				store.Stores{Keys: keyStore},
				&stubPreparer{},
				keyoperator.ApplyKeyActionRequest{
					TenantID:     tenantID,
					KeyID:        root.ID,
					ToState:      model.KeyLifeCycleActive,
					KeyFilters:   activateFilter,
					Cascading:    true,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
			)

			assert.Empty(t, got)
			assert.ErrorIs(t, err, keyoperator.ErrNoKeysFound)
		})
	})

	// ── already-completed parent must be skipped ────────────────────────
	t.Run("already-completed parent is skipped not excluded", func(t *testing.T) {
		// given — root is already at target state (Active + Completed);
		// it should be skipped (children remain reachable), not excluded.
		//
		//  root (active + completed) ← skipped
		//    \
		//     child (pre-activation + completed) ← activatable
		root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
			model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		child := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     tenantID,
				KeyID:        root.ID,
				ToState:      model.KeyLifeCycleActive,
				KeyFilters:   activateFilter,
				Cascading:    true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		// Root should be SKIPPED (not excluded), child should be activated.
		require.NoError(t, err)
		assert.Equal(t, activatekey.JobGroupType, got.Type)
		require.Len(t, got.Jobs, 1)
		assert.Equal(t, activatekey.JobType, got.Jobs[0].Type)
		assertJobDataContainsKeys(t, got.Jobs[0].Data, child.ID)
		assertJobDataTenantID(t, got.Jobs[0].Data, tenantID)
	})

	// ── PrepareJobGroup error ───────────────────────────────────────────
	t.Run("PrepareJobGroup error propagates", func(t *testing.T) {
		errPrepare := errors.New("prepare failed")

		key := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&failPreparer{err: errPrepare},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     tenantID,
				KeyID:        key.ID,
				ToState:      model.KeyLifeCycleActive,
				KeyFilters:   activateFilter,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		assert.Empty(t, got)
		assert.ErrorIs(t, err, errPrepare)
	})

	// ── success ─────────────────────────────────────────────────────────
	t.Run("success", func(t *testing.T) {
		t.Run("non-cascading: pre-activation to active", func(t *testing.T) {
			key := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
				model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

			got, err := keyoperator.ApplyKeyAction(
				t.Context(),
				store.Stores{Keys: keyStore},
				&stubPreparer{},
				keyoperator.ApplyKeyActionRequest{
					TenantID:     tenantID,
					KeyID:        key.ID,
					ToState:      model.KeyLifeCycleActive,
					KeyFilters:   activateFilter,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
			)

			require.NoError(t, err)
			assert.Equal(t, activatekey.JobGroupType, got.Type)
			require.Len(t, got.Jobs, 1)
			assert.Equal(t, activatekey.JobType, got.Jobs[0].Type)
			assertJobDataContainsKeys(t, got.Jobs[0].Data, key.ID)
			assertJobDataTenantID(t, got.Jobs[0].Data, tenantID)
		})

		t.Run("non-cascading: suspended to active (re-activation)", func(t *testing.T) {
			key := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
				model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

			got, err := keyoperator.ApplyKeyAction(
				t.Context(),
				store.Stores{Keys: keyStore},
				&stubPreparer{},
				keyoperator.ApplyKeyActionRequest{
					TenantID:     tenantID,
					KeyID:        key.ID,
					ToState:      model.KeyLifeCycleActive,
					KeyFilters:   activateFilter,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
			)

			require.NoError(t, err)
			assert.Equal(t, activatekey.JobGroupType, got.Type)
			require.Len(t, got.Jobs, 1)
			assert.Equal(t, activatekey.JobType, got.Jobs[0].Type)
			assertJobDataContainsKeys(t, got.Jobs[0].Data, key.ID)
			assertJobDataTenantID(t, got.Jobs[0].Data, tenantID)
		})

		t.Run("non-cascading: active key with failed processing is retried", func(t *testing.T) {
			key := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
				model.KeyLifeCycleActive, model.KeyProcessingFailed)

			got, err := keyoperator.ApplyKeyAction(
				t.Context(),
				store.Stores{Keys: keyStore},
				&stubPreparer{},
				keyoperator.ApplyKeyActionRequest{
					TenantID:     tenantID,
					KeyID:        key.ID,
					ToState:      model.KeyLifeCycleActive,
					KeyFilters:   activateFilter,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
			)

			require.NoError(t, err)
			assert.Equal(t, activatekey.JobGroupType, got.Type)
			require.Len(t, got.Jobs, 1)
			assert.Equal(t, activatekey.JobType, got.Jobs[0].Type)
			assertJobDataContainsKeys(t, got.Jobs[0].Data, key.ID)
			assertJobDataTenantID(t, got.Jobs[0].Data, tenantID)
		})

		t.Run("cascading: multi-layer tree fully activated", func(t *testing.T) {
			root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
				model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
			child := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
				model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

			got, err := keyoperator.ApplyKeyAction(
				t.Context(),
				store.Stores{Keys: keyStore},
				&stubPreparer{},
				keyoperator.ApplyKeyActionRequest{
					TenantID:     tenantID,
					KeyID:        root.ID,
					ToState:      model.KeyLifeCycleActive,
					KeyFilters:   activateFilter,
					Cascading:    true,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
			)

			require.NoError(t, err)
			assert.Equal(t, activatekey.JobGroupType, got.Type)
			require.Len(t, got.Jobs, 2)
			assertJobDataContainsKeys(t, got.Jobs[0].Data, root.ID)
			assertJobDataContainsKeys(t, got.Jobs[1].Data, child.ID)
			for _, job := range got.Jobs {
				assertJobDataTenantID(t, job.Data, tenantID)
			}
		})

		t.Run("cascading: already-completed root skipped, child still activated", func(t *testing.T) {
			root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
				model.KeyLifeCycleActive, model.KeyProcessingCompleted)
			child := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
				model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

			got, err := keyoperator.ApplyKeyAction(
				t.Context(),
				store.Stores{Keys: keyStore},
				&stubPreparer{},
				keyoperator.ApplyKeyActionRequest{
					TenantID:     tenantID,
					KeyID:        root.ID,
					ToState:      model.KeyLifeCycleActive,
					KeyFilters:   activateFilter,
					Cascading:    true,
					JobType:      activatekey.JobType,
					JobGroupType: activatekey.JobGroupType,
				},
			)

			require.NoError(t, err)
			require.Len(t, got.Jobs, 1, "only child layer; root is skipped")
			assertJobDataContainsKeys(t, got.Jobs[0].Data, child.ID)
			assertJobDataTenantID(t, got.Jobs[0].Data, tenantID)
		})
	})
}

// ── cascading multi-layer: all keys included ────────────────────────────
func TestApplyKeyAction_CascadingMultiLayerAllIncluded(t *testing.T) {
	db := createDatabase(t)
	tenantID := createTenant(t, db)
	keyStore := storesql.NewKeyStore(db)

	t.Run("wide tree: two branches across 3 layers with mixed activatable states", func(t *testing.T) {
		// given — all keys can transition to active, mixed pre-activation and suspended.
		//
		//                 root (pre-activation + completed)
		//                /                                 \
		//   child-A (pre-activation + completed)   child-B (suspended + completed)
		//        |                                       |
		//   grand-A (pre-activation + completed)   grand-B (pre-activation + completed)
		root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childA := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childB := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		grandA := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childA.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		grandB := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childB.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     tenantID,
				KeyID:        root.ID,
				ToState:      model.KeyLifeCycleActive,
				KeyFilters:   activateFilter,
				Cascading:    true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		require.NoError(t, err)
		assert.Equal(t, activatekey.JobGroupType, got.Type)
		require.Len(t, got.Jobs, 3, "one job per layer")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, root.ID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childA.ID, childB.ID)
		assertJobDataContainsKeys(t, got.Jobs[2].Data, grandA.ID, grandB.ID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, tenantID)
		}
	})

	t.Run("deep tree: 4 layers single chain all activatable", func(t *testing.T) {
		// given — linear chain, each layer has exactly one key.
		//
		//   root (pre-activation + completed)
		//     └── child (suspended + completed)
		//           └── grand (pre-activation + completed)
		//                 └── great (pre-activation + completed)
		root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		child := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		grand := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &child.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		great := seedKey(t, keyStore, tenantID, uuid.New().String(), "K3", &grand.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     tenantID,
				KeyID:        root.ID,
				ToState:      model.KeyLifeCycleActive,
				KeyFilters:   activateFilter,
				Cascading:    true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		require.NoError(t, err)
		require.Len(t, got.Jobs, 4, "one job per layer")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, root.ID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, child.ID)
		assertJobDataContainsKeys(t, got.Jobs[2].Data, grand.ID)
		assertJobDataContainsKeys(t, got.Jobs[3].Data, great.ID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, tenantID)
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
		root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childA := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childB := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		grandA1 := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childA.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		grandA2 := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childA.ID,
			model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		grandB1 := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childB.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		greatA1 := seedKey(t, keyStore, tenantID, uuid.New().String(), "K3", &grandA1.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     tenantID,
				KeyID:        root.ID,
				ToState:      model.KeyLifeCycleActive,
				KeyFilters:   activateFilter,
				Cascading:    true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		require.NoError(t, err)
		require.Len(t, got.Jobs, 4, "one job per layer")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, root.ID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childA.ID, childB.ID)
		assertJobDataContainsKeys(t, got.Jobs[2].Data, grandA1.ID, grandA2.ID, grandB1.ID)
		assertJobDataContainsKeys(t, got.Jobs[3].Data, greatA1.ID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, tenantID)
		}
	})

	t.Run("wide and deep tree: destroyed grandchild excluded, rest activated", func(t *testing.T) {
		// given — grand-A1 is destroyed (excluded by filter), so great-A1
		// is cascade-excluded too (unreachable in the recursive CTE).
		//
		//                         root (pre-activation + completed)
		//                        /                                  \
		//       child-A (pre-activation + completed)         child-B (pre-activation + completed)
		//          /                    \                          |
		//   grand-A1 (destroyed + comp)  grand-A2 (suspended + comp)  grand-B1 (pre-act + comp)
		//        |
		//   great-A1 (pre-act + comp) ← cascade-excluded (parent grand-A1 excluded)
		root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childA := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childB := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		grandA1 := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childA.ID,
			model.KeyLifeCycleDestroyed, model.KeyProcessingCompleted)
		grandA2 := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childA.ID,
			model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		grandB1 := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childB.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		seedKey(t, keyStore, tenantID, uuid.New().String(), "K3", &grandA1.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted) // great-A1: cascade-excluded

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     tenantID,
				KeyID:        root.ID,
				ToState:      model.KeyLifeCycleActive,
				KeyFilters:   activateFilter,
				Cascading:    true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		// grand-A1 excluded (destroyed), great-A1 cascade-excluded (parent excluded)
		// remaining 5 keys: root, child-A, child-B, grand-A2, grand-B1
		require.NoError(t, err)
		require.Len(t, got.Jobs, 3, "3 jobs: layers 0, 1, 2 (layer 3 all excluded)")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, root.ID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childA.ID, childB.ID)
		assertJobDataContainsKeys(t, got.Jobs[2].Data, grandA2.ID, grandB1.ID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, tenantID)
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
		root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
			model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		childA := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childB := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		grandA := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childA.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		grandB := seedKey(t, keyStore, tenantID, uuid.New().String(), "K2", &childB.ID,
			model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     tenantID,
				KeyID:        root.ID,
				ToState:      model.KeyLifeCycleActive,
				KeyFilters:   activateFilter,
				Cascading:    true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		// root is skipped (already active + completed), but children and grandchildren are activated
		require.NoError(t, err)
		require.Len(t, got.Jobs, 2, "two jobs: layer 1 and layer 2 (root layer produces no job)")
		assertJobDataContainsKeys(t, got.Jobs[0].Data, childA.ID, childB.ID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, grandA.ID, grandB.ID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, tenantID)
		}
	})

	t.Run("failed processing retry mixed with fresh activation across branches", func(t *testing.T) {
		// given — root has failed processing (retry), children are fresh pre-activation.
		//
		//              root (active + failed) ← retried
		//             /                        \
		//   child-A (pre-act + comp)     child-B (pre-act + comp)
		root := seedKey(t, keyStore, tenantID, uuid.New().String(), "K0", nil,
			model.KeyLifeCycleActive, model.KeyProcessingFailed)
		childA := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childB := seedKey(t, keyStore, tenantID, uuid.New().String(), "K1", &root.ID,
			model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		got, err := keyoperator.ApplyKeyAction(
			t.Context(),
			store.Stores{Keys: keyStore},
			&stubPreparer{},
			keyoperator.ApplyKeyActionRequest{
				TenantID:     tenantID,
				KeyID:        root.ID,
				ToState:      model.KeyLifeCycleActive,
				KeyFilters:   activateFilter,
				Cascading:    true,
				JobType:      activatekey.JobType,
				JobGroupType: activatekey.JobGroupType,
			},
		)

		require.NoError(t, err)
		require.Len(t, got.Jobs, 2)
		assertJobDataContainsKeys(t, got.Jobs[0].Data, root.ID)
		assertJobDataContainsKeys(t, got.Jobs[1].Data, childA.ID, childB.ID)
		for _, job := range got.Jobs {
			assertJobDataTenantID(t, job.Data, tenantID)
		}
	})
}

// stubPreparer is a no-op JobGroupPreparer that returns the group as-is.
type stubPreparer struct{}

func (*stubPreparer) PrepareJobGroup(_ context.Context, group orbital.JobGroup) (orbital.JobGroup, error) {
	return group, nil
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
