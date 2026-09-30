package activatekey_test

import (
	"encoding/json/v2"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler/activatekey"
)

func TestBuildJobGroup_OneJobPerLayerRootToLeaf(t *testing.T) {
	db := newRootDB(t)
	s := newStores(t, db)
	tenant := seedTenant(t, s.tenantStore)

	k0 := seedKey(t, s.keyStore, tenant.ID, "k0", "K0", testRootName, nil)
	k1 := seedKey(t, s.keyStore, tenant.ID, "k1", "K1", testRootName, &k0.ID)
	k2 := seedKey(t, s.keyStore, tenant.ID, "k2", "K2", testRootName, &k1.ID)

	group, err := activatekey.BuildJobGroup(t.Context(), s.keyStore, tenant.ID, k0.ID)
	require.NoError(t, err)

	assert.Equal(t, activatekey.GroupType, group.Type)
	require.Len(t, group.Jobs, 3, "k0 -> k1 -> k2 is three layers")

	// Layers are ordered root to leaf, one key per layer here.
	wantOrder := []string{k0.ID, k1.ID, k2.ID}
	for i, job := range group.Jobs {
		assert.Equal(t, activatekey.JobType, job.Type)
		var layer activatekey.LayerData
		require.NoError(t, json.Unmarshal(job.Data, &layer))
		assert.Equal(t, tenant.ID, layer.TenantID)
		assert.Equal(t, k0.ID, layer.RootKeyID)
		require.Len(t, layer.KeyIDs, 1)
		assert.Equal(t, wantOrder[i], layer.KeyIDs[0], "layer %d out of order", i)
	}
}

func TestBuildJobGroup_AnchoredAtIntermediateExcludesAncestors(t *testing.T) {
	db := newRootDB(t)
	s := newStores(t, db)
	tenant := seedTenant(t, s.tenantStore)

	k0 := seedKey(t, s.keyStore, tenant.ID, "k0", "K0", testRootName, nil)
	k1 := seedKey(t, s.keyStore, tenant.ID, "k1", "K1", testRootName, &k0.ID)
	_ = seedKey(t, s.keyStore, tenant.ID, "k2", "K2", testRootName, &k1.ID)

	group, err := activatekey.BuildJobGroup(t.Context(), s.keyStore, tenant.ID, k1.ID)
	require.NoError(t, err)
	assert.Len(t, group.Jobs, 2, "anchored at k1: k1 -> k2 is two layers")
}

func TestBuildJobGroup_MultipleKeysInOneLayer(t *testing.T) {
	db := newRootDB(t)
	s := newStores(t, db)
	tenant := seedTenant(t, s.tenantStore)

	k0 := seedKey(t, s.keyStore, tenant.ID, "k0", "K0", testRootName, nil)
	_ = seedKey(t, s.keyStore, tenant.ID, "k1a", "K1", testRootName, &k0.ID)
	_ = seedKey(t, s.keyStore, tenant.ID, "k1b", "K1", testRootName, &k0.ID)

	group, err := activatekey.BuildJobGroup(t.Context(), s.keyStore, tenant.ID, k0.ID)
	require.NoError(t, err)
	require.Len(t, group.Jobs, 2, "root layer + a single child layer with two keys")

	var childLayer activatekey.LayerData
	require.NoError(t, json.Unmarshal(group.Jobs[1].Data, &childLayer))
	assert.Len(t, childLayer.KeyIDs, 2, "both K1 siblings share one layer")
}

func TestBuildJobGroup_UnknownKey(t *testing.T) {
	db := newRootDB(t)
	s := newStores(t, db)
	tenant := seedTenant(t, s.tenantStore)

	_, err := activatekey.BuildJobGroup(t.Context(), s.keyStore, tenant.ID, uuid.New().String())
	require.Error(t, err)
	assert.ErrorIs(t, err, activatekey.ErrNoKeys, "want ErrNoKeys, got %v", err)
}
