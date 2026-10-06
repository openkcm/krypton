package keyoperator_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

func TestFilterKeyTree(t *testing.T) {
	const (
		tenantID = "t-1"
		rootID   = "root"
		childAID = "childA"
		childBID = "childB"
		grandAID = "grandA"
		grandBID = "grandB"
	)

	ptr := func(s string) *string { return &s }

	t.Run("should return error ErrInternal if state is nil", func(t *testing.T) {
		// given
		root := model.Key{
			ID:             "root",
			TenantID:       testTenantID,
			LifeCycleState: model.KeyLifeCyclePreActivation,
			KeyProcessingState: model.KeyProcessingState{
				Status: model.KeyProcessingCompleted,
			},
		}
		keys := &stubKeyStore{
			getDescendantKeys: func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
				return store.GetDescendantKeysResult{KeyTree: model.KeyTree{{root}}}, nil
			},
		}
		step := keyoperator.FilterKeyTree(testTenantID, "root", model.KeyLifeCycleActive, model.KeyProcessingCompleted, nil)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then
		assert.Error(t, err)
		assert.ErrorIs(t, err, keyoperator.ErrInternal)
	})

	t.Run("should return error when GetDescendantKeys fails", func(t *testing.T) {
		// given
		keys := &stubKeyStore{
			getDescendantKeys: stubDescendantsErr(store.ErrKeyNotFound),
		}
		state := keyoperator.NewFilterKeyTreeState()
		step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return one layer when key has no descendants", func(t *testing.T) {
		// given
		root := testKey(rootID, tenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		keys := &stubKeyStore{
			getDescendantKeys: stubDescendants(model.KeyTree{{root}}),
		}
		state := keyoperator.NewFilterKeyTreeState()
		step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then
		require.NoError(t, err)
		require.Len(t, state.Tree, 1)
		assertLayerContainsKeys(t, state.Tree[0], rootID)
		assert.False(t, state.IsChildrenExcluded)
	})

	t.Run("should return layers for each depth of descendants", func(t *testing.T) {
		// given — root -> child -> grandchild, all pre-activation + completed.
		root := testKey(rootID, tenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		child := testKey(childAID, tenantID, ptr(rootID), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		grandchild := testKey(grandAID, tenantID, ptr(childAID), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		keys := &stubKeyStore{
			getDescendantKeys: stubDescendants(model.KeyTree{{root}, {child}, {grandchild}}),
		}
		state := keyoperator.NewFilterKeyTreeState()
		step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then — 3 layers: root, child, grandchild.
		require.NoError(t, err)
		require.Len(t, state.Tree, 3)
		assertLayerContainsKeys(t, state.Tree[0], rootID)
		assertLayerContainsKeys(t, state.Tree[1], childAID)
		assertLayerContainsKeys(t, state.Tree[2], grandAID)
		assert.False(t, state.IsChildrenExcluded)
	})

	t.Run("should include multiple keys in the same layer", func(t *testing.T) {
		// given — root with two children at the same depth.
		root := testKey(rootID, tenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childA := testKey(childAID, tenantID, ptr(rootID), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childB := testKey(childBID, tenantID, ptr(rootID), model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		keys := &stubKeyStore{
			getDescendantKeys: stubDescendants(model.KeyTree{{root}, {childA, childB}}),
		}
		state := keyoperator.NewFilterKeyTreeState()
		step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then — layer 0: root, layer 1: childA + childB.
		require.NoError(t, err)
		require.Len(t, state.Tree, 2)
		assertLayerContainsKeys(t, state.Tree[0], rootID)
		assertLayerContainsKeys(t, state.Tree[1], childAID, childBID)
		assert.False(t, state.IsChildrenExcluded)
	})

	t.Run("should exclude keys with pending processing", func(t *testing.T) {
		// given — root (valid) with two children: one completed, one pending.
		root := testKey(rootID, tenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		validChild := testKey(childAID, tenantID, ptr(rootID), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		pendingChild := testKey(childBID, tenantID, ptr(rootID), model.KeyLifeCyclePreActivation, model.KeyProcessingPending)
		keys := &stubKeyStore{
			getDescendantKeys: stubDescendants(model.KeyTree{{root}, {validChild, pendingChild}}),
		}
		state := keyoperator.NewFilterKeyTreeState()
		step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then — pending child is excluded.
		require.NoError(t, err)
		require.Len(t, state.Tree, 2)
		assertLayerContainsKeys(t, state.Tree[0], rootID)
		assertLayerContainsKeys(t, state.Tree[1], childAID)
		assert.True(t, state.IsChildrenExcluded)
	})

	t.Run("should exclude keys in", func(t *testing.T) {
		tts := []struct {
			name           string
			childLifecycle model.KeyLifeCycleState
		}{
			{name: "deactivated state", childLifecycle: model.KeyLifeCycleDeactivated},
			{name: "destroyed state", childLifecycle: model.KeyLifeCycleDestroyed},
			{name: "compromised state", childLifecycle: model.KeyLifeCycleCompromised},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given — root (valid) with one child in the given excluded lifecycle state.
				root := testKey(rootID, tenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
				child := testKey(childAID, tenantID, ptr(rootID), tt.childLifecycle, model.KeyProcessingCompleted)
				keys := &stubKeyStore{
					getDescendantKeys: stubDescendants(model.KeyTree{{root}, {child}}),
				}
				state := keyoperator.NewFilterKeyTreeState()
				step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

				// when
				err := step(t.Context(), store.Stores{Keys: keys})

				// then — only root layer remains; child layer is skipped.
				require.NoError(t, err)
				require.Len(t, state.Tree, 1)
				assertLayerContainsKeys(t, state.Tree[0], rootID)
				assert.True(t, state.IsChildrenExcluded)
			})
		}
	})

	t.Run("should include keys in", func(t *testing.T) {
		tts := []struct {
			name           string
			childLifecycle model.KeyLifeCycleState
		}{
			{name: "pre-activation state", childLifecycle: model.KeyLifeCyclePreActivation},
			{name: "active state", childLifecycle: model.KeyLifeCycleActive},
			{name: "suspended state", childLifecycle: model.KeyLifeCycleSuspended},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given — root (valid) with a child in the given lifecycle + completed processing.
				root := testKey(rootID, tenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
				child := testKey(childAID, tenantID, ptr(rootID), tt.childLifecycle, model.KeyProcessingCompleted)
				keys := &stubKeyStore{
					getDescendantKeys: stubDescendants(model.KeyTree{{root}, {child}}),
				}
				state := keyoperator.NewFilterKeyTreeState()
				step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

				// when
				err := step(t.Context(), store.Stores{Keys: keys})

				// then — child is included.
				require.NoError(t, err)
				require.Len(t, state.Tree, 2)
				assertLayerContainsKeys(t, state.Tree[0], rootID)
				assertLayerContainsKeys(t, state.Tree[1], childAID)
				assert.False(t, state.IsChildrenExcluded)
			})
		}
	})

	t.Run("should include valid branch and exclude invalid branch at the same layer", func(t *testing.T) {
		// given — root with two branches:
		//
		//              root (pre-activation + completed)
		//              /                               \
		//   childA (pre-activation + completed)   childB (deactivated + completed)
		//        |                                      |
		//   grandA (pre-activation + completed)   grandB (pre-activation + completed)
		//
		// childB is excluded (deactivated cannot transition to active).
		// grandB is excluded because its parent childB was excluded.
		root := testKey(rootID, tenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childA := testKey(childAID, tenantID, ptr(rootID), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		childB := testKey(childBID, tenantID, ptr(rootID), model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		grandA := testKey(grandAID, tenantID, ptr(childAID), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		grandB := testKey(grandBID, tenantID, ptr(childBID), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
		keys := &stubKeyStore{
			getDescendantKeys: stubDescendants(model.KeyTree{
				{root},
				{childA, childB},
				{grandA, grandB},
			}),
		}
		state := keyoperator.NewFilterKeyTreeState()
		step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then — 3 layers:
		// layer 0: root
		// layer 1: only childA (childB excluded — deactivated cannot transition to active)
		// layer 2: only grandA (grandB excluded — parent childB was excluded)
		require.NoError(t, err)
		require.Len(t, state.Tree, 3)
		assertLayerContainsKeys(t, state.Tree[0], rootID)
		assertLayerContainsKeys(t, state.Tree[1], childAID)
		assertLayerContainsKeys(t, state.Tree[2], grandAID)
		assert.True(t, state.IsChildrenExcluded)
	})

	t.Run("should return ErrNoKeyTreeFound when all keys are excluded", func(t *testing.T) {
		// given — root is destroyed + completed (excluded), no other descendants.
		root := testKey(rootID, tenantID, nil, model.KeyLifeCycleDestroyed, model.KeyProcessingCompleted)
		keys := &stubKeyStore{
			getDescendantKeys: stubDescendants(model.KeyTree{{root}}),
		}
		state := keyoperator.NewFilterKeyTreeState()
		step := keyoperator.FilterKeyTree(tenantID, rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted, state)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, keyoperator.ErrKeyTreeNotFound)
	})
}

// testKey builds a model.Key with the given lifecycle and processing state.
func testKey(id, tenantID string, parentID *string, lc model.KeyLifeCycleState, ps model.KeyProcessingStatus) model.Key {
	return model.Key{
		ID:             id,
		TenantID:       tenantID,
		ParentID:       parentID,
		LifeCycleState: lc,
		KeyProcessingState: model.KeyProcessingState{
			Status: ps,
		},
	}
}

// stubDescendants returns a getDescendantKeys stub that returns the given
// key tree layers as a GetDescendantKeysResult.
func stubDescendants(layers model.KeyTree) func(context.Context, store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
	return func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
		return store.GetDescendantKeysResult{KeyTree: layers}, nil
	}
}

// stubDescendantsErr returns a getDescendantKeys stub that always fails.
func stubDescendantsErr(err error) func(context.Context, store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
	return func(_ context.Context, _ store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
		return store.GetDescendantKeysResult{}, err
	}
}

// assertLayerContainsKeys verifies a key tree layer contains exactly the
// given key IDs (order-independent).
func assertLayerContainsKeys(t *testing.T, layer []model.Key, expectedKeyIDs ...string) {
	t.Helper()
	actualIDs := make([]string, 0, len(layer))
	for _, key := range layer {
		actualIDs = append(actualIDs, key.ID)
	}
	assert.ElementsMatch(t, expectedKeyIDs, actualIDs)
}

func TestUpdateKeyTree_NilRetriever(t *testing.T) {
	t.Run("should return ErrNoKeyTreeFound when ret is nil", func(t *testing.T) {
		// given
		step := keyoperator.UpdateKeyTree(nil, model.KeyLifeCycleActive, model.KeyProcessingPending)

		// when
		err := step(t.Context(), store.Stores{Keys: &stubKeyStore{}})

		// then
		assert.Error(t, err)
		assert.ErrorIs(t, err, keyoperator.ErrKeyTreeNotFound)
	})

	t.Run("should return ErrNoKeyTreeFound when ret is empty", func(t *testing.T) {
		// given
		state := keyoperator.NewFilterKeyTreeState()
		step := keyoperator.UpdateKeyTree(state, model.KeyLifeCycleActive, model.KeyProcessingPending)

		// when
		err := step(t.Context(), store.Stores{Keys: &stubKeyStore{}})

		// then
		assert.Error(t, err)
		assert.ErrorIs(t, err, keyoperator.ErrKeyTreeNotFound)
	})

	t.Run("should return error when UpdateKeyStates fails", func(t *testing.T) {
		// given
		errBoom := errors.New("boom")
		state := keyoperator.NewFilterKeyTreeState()
		state.Tree = model.KeyTree{
			{testKey("k1", testTenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)},
		}
		keys := &stubKeyStore{
			updateKeyStates: func(_ context.Context, _ store.UpdateKeyStatesQuery) error {
				return errBoom
			},
		}
		step := keyoperator.UpdateKeyTree(state, model.KeyLifeCycleActive, model.KeyProcessingPending)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, errBoom)
		assert.Contains(t, err.Error(), "updating key k1 state")
	})

	t.Run("should update all keys in tree successfully", func(t *testing.T) {
		// given
		ptr := func(s string) *string { return &s }
		state := keyoperator.NewFilterKeyTreeState()
		state.Tree = model.KeyTree{
			{testKey("root", testTenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)},
			{
				testKey("childA", testTenantID, ptr("root"), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted),
				testKey("childB", testTenantID, ptr("root"), model.KeyLifeCycleSuspended, model.KeyProcessingCompleted),
			},
		}
		var queries []store.UpdateKeyStatesQuery
		keys := &stubKeyStore{
			updateKeyStates: func(_ context.Context, q store.UpdateKeyStatesQuery) error {
				queries = append(queries, q)
				return nil
			},
		}
		step := keyoperator.UpdateKeyTree(state, model.KeyLifeCycleActive, model.KeyProcessingPending)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then
		require.NoError(t, err)
		require.Len(t, queries, 3)

		// root: pre-activation + completed -> active + pending
		assert.Equal(t, "root", queries[0].ID)
		assert.Equal(t, testTenantID, queries[0].TenantID)
		assert.Equal(t, model.KeyLifeCycleActive, queries[0].ToState)
		assert.Equal(t, model.KeyProcessingPending, queries[0].ToStatus)
		assert.Equal(t, []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation}, queries[0].FromState)
		assert.Equal(t, []model.KeyProcessingStatus{model.KeyProcessingCompleted}, queries[0].FromStatus)

		// childA: pre-activation + completed -> active + pending
		assert.Equal(t, "childA", queries[1].ID)
		assert.Equal(t, model.KeyLifeCycleActive, queries[1].ToState)
		assert.Equal(t, model.KeyProcessingPending, queries[1].ToStatus)
		assert.Equal(t, []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation}, queries[1].FromState)
		assert.Equal(t, []model.KeyProcessingStatus{model.KeyProcessingCompleted}, queries[1].FromStatus)

		// childB: suspended + completed -> active + pending
		assert.Equal(t, "childB", queries[2].ID)
		assert.Equal(t, model.KeyLifeCycleActive, queries[2].ToState)
		assert.Equal(t, model.KeyProcessingPending, queries[2].ToStatus)
		assert.Equal(t, []model.KeyLifeCycleState{model.KeyLifeCycleSuspended}, queries[2].FromState)
		assert.Equal(t, []model.KeyProcessingStatus{model.KeyProcessingCompleted}, queries[2].FromStatus)
	})

	t.Run("should return error when KeyTree retriever fails", func(t *testing.T) {
		// given — a custom retriever that returns a non-standard error.
		errCustom := errors.New("retriever broken")
		ret := &failingRetriever{err: errCustom}
		step := keyoperator.UpdateKeyTree(ret, model.KeyLifeCycleActive, model.KeyProcessingPending)

		// when
		err := step(t.Context(), store.Stores{Keys: &stubKeyStore{}})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, errCustom)
	})

	t.Run("should stop on first UpdateKeyStates failure", func(t *testing.T) {
		// given — two keys in the same layer; UpdateKeyStates fails on the second.
		errBoom := errors.New("boom")
		state := keyoperator.NewFilterKeyTreeState()
		state.Tree = model.KeyTree{
			{
				testKey("k1", testTenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted),
				testKey("k2", testTenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted),
			},
		}
		var updatedKeys []string
		keys := &stubKeyStore{
			updateKeyStates: func(_ context.Context, q store.UpdateKeyStatesQuery) error {
				updatedKeys = append(updatedKeys, q.ID)
				if q.ID == "k2" {
					return errBoom
				}
				return nil
			},
		}
		step := keyoperator.UpdateKeyTree(state, model.KeyLifeCycleActive, model.KeyProcessingPending)

		// when
		err := step(t.Context(), store.Stores{Keys: keys})

		// then — k1 succeeded, k2 failed, no further keys processed.
		require.Error(t, err)
		assert.ErrorIs(t, err, errBoom)
		assert.Equal(t, []string{"k1", "k2"}, updatedKeys)
	})
}

// failingRetriever is a KeyTreeRetriever stub that always returns an error.
type failingRetriever struct {
	err error
}

func (f *failingRetriever) KeyTree() (model.KeyTree, error) {
	return nil, f.err
}

// stubPreparer is a JobGroupPreparer stub.
type stubPreparer struct {
	err error
}

func (s *stubPreparer) PrepareJobGroup(_ context.Context, grp orbital.JobGroup) (orbital.JobGroup, error) {
	if s.err != nil {
		return orbital.JobGroup{}, s.err
	}
	return grp, nil
}

func TestPrepareKeyTreeJobGroup(t *testing.T) {
	validRetriever := keyoperator.NewFilterKeyTreeState()
	validRetriever.Tree = model.KeyTree{
		{testKey("k1", testTenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)},
	}

	t.Run("should return ErrInternal when a required argument is nil", func(t *testing.T) {
		tts := []struct {
			name     string
			preparer keyoperator.JobGroupPreparer
			ret      keyoperator.KeyTreeRetriever
			state    *keyoperator.PrepareKeyTreeJobsState
		}{
			{
				name:     "ret is nil",
				preparer: &stubPreparer{},
				ret:      nil,
				state:    keyoperator.NewPrepareKeyTreeJobsState(),
			},
			{
				name:     "preparer is nil",
				preparer: nil,
				ret:      validRetriever,
				state:    keyoperator.NewPrepareKeyTreeJobsState(),
			},
			{
				name:     "state is nil",
				preparer: &stubPreparer{},
				ret:      validRetriever,
				state:    nil,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				step := keyoperator.PrepareKeyTreeJobGroup(tt.preparer, tt.ret, tt.state)

				// when
				err := step(t.Context(), store.Stores{})

				// then
				require.Error(t, err)
				assert.ErrorIs(t, err, keyoperator.ErrInternal)
			})
		}
	})

	t.Run("should return error when KeyTree retriever fails", func(t *testing.T) {
		// given
		errCustom := errors.New("retriever broken")
		step := keyoperator.PrepareKeyTreeJobGroup(
			&stubPreparer{},
			&failingRetriever{err: errCustom},
			keyoperator.NewPrepareKeyTreeJobsState(),
		)

		// when
		err := step(t.Context(), store.Stores{})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, errCustom)
	})

	t.Run("should return ErrNoKeyTreeFound when KeyTree is empty", func(t *testing.T) {
		// given — retriever with an empty tree.
		step := keyoperator.PrepareKeyTreeJobGroup(
			&stubPreparer{},
			keyoperator.NewFilterKeyTreeState(),
			keyoperator.NewPrepareKeyTreeJobsState(),
		)

		// when
		err := step(t.Context(), store.Stores{})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, keyoperator.ErrKeyTreeNotFound)
	})

	t.Run("should return error when PrepareJobGroup fails", func(t *testing.T) {
		// given
		errBoom := errors.New("preparer failed")
		step := keyoperator.PrepareKeyTreeJobGroup(
			&stubPreparer{err: errBoom},
			validRetriever,
			keyoperator.NewPrepareKeyTreeJobsState(),
		)

		// when
		err := step(t.Context(), store.Stores{})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, errBoom)
	})

	t.Run("should prepare job group successfully", func(t *testing.T) {
		// given — two-layer tree: root + two children.
		ptr := func(s string) *string { return &s }
		filterState := keyoperator.NewFilterKeyTreeState()
		filterState.Tree = model.KeyTree{
			{testKey("root", testTenantID, nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)},
			{
				testKey("childA", testTenantID, ptr("root"), model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted),
				testKey("childB", testTenantID, ptr("root"), model.KeyLifeCycleSuspended, model.KeyProcessingCompleted),
			},
		}
		prepareState := keyoperator.NewPrepareKeyTreeJobsState()
		step := keyoperator.PrepareKeyTreeJobGroup(
			&stubPreparer{},
			filterState,
			prepareState,
		)

		// when
		err := step(t.Context(), store.Stores{})

		// then
		require.NoError(t, err)
		require.Len(t, prepareState.JobGroup.Jobs, 2, "one job per layer")

		// job 0: layer 0 — root only.
		var layer0 []model.Key
		require.NoError(t, json.Unmarshal(prepareState.JobGroup.Jobs[0].Data, &layer0))
		assertLayerContainsKeys(t, layer0, "root")

		// job 1: layer 1 — childA + childB.
		var layer1 []model.Key
		require.NoError(t, json.Unmarshal(prepareState.JobGroup.Jobs[1].Data, &layer1))
		assertLayerContainsKeys(t, layer1, "childA", "childB")
	})
}
