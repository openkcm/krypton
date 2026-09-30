package keys_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// seedKey inserts a key directly into the root store, bypassing announce
// validation, so tests can build a hierarchy without activating each layer.
func seedKey(t *testing.T, keyStore store.Key, tenantID, name, kind string, parentID *string) string {
	t.Helper()
	key := model.NewKey(tenantID, name+"-"+uuid.New().String(), kind, parentID, "root", nil)
	key.LifeCycleState = model.KeyLifeCyclePreActivation
	require.NoError(t, keyStore.CreateKey(t.Context(), key))
	return key.ID
}

// TestActivateKey covers the admin ActivateKey RPC's new contract: it builds a
// cascading activation job group (one job per hierarchy layer, root to leaf) and
// hands it to the orchestrator, returning the group ID. The per-key sealing is
// exercised in the activate-key task handler tests, not here.
func TestActivateKey(t *testing.T) {
	ctx := t.Context()
	rootTopology := rootTestTopology()

	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))

	t.Run("enqueues a single-layer group for a leaf root key", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, &rootTopology)
		tenant := createTenant(t, setup.tenantStore)

		rootID := seedKey(t, setup.keyStore, tenant.ID, "root-key", "K0", nil)

		res, err := setup.cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       rootID,
		})
		require.NoError(t, err)

		require.Len(t, spy.groups, 1)
		assert.Equal(t, spy.groups[0].ID.String(), res.GetJobGroupId())
		assert.Len(t, spy.groups[0].Jobs, 1, "a lone key is one layer")
	})

	t.Run("enqueues one job per hierarchy layer, root to leaf", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, &rootTopology)
		tenant := createTenant(t, setup.tenantStore)

		k0 := seedKey(t, setup.keyStore, tenant.ID, "k0", "K0", nil)
		k1 := seedKey(t, setup.keyStore, tenant.ID, "k1", "K1", &k0)
		_ = seedKey(t, setup.keyStore, tenant.ID, "k2", "K2", &k1)

		res, err := setup.cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       k0,
		})
		require.NoError(t, err)

		require.Len(t, spy.groups, 1)
		assert.NotEmpty(t, res.GetJobGroupId())
		assert.Len(t, spy.groups[0].Jobs, 3, "k0 -> k1 -> k2 is three layers")
	})

	t.Run("group anchored at an intermediate key excludes ancestors", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, &rootTopology)
		tenant := createTenant(t, setup.tenantStore)

		k0 := seedKey(t, setup.keyStore, tenant.ID, "k0", "K0", nil)
		k1 := seedKey(t, setup.keyStore, tenant.ID, "k1", "K1", &k0)
		_ = seedKey(t, setup.keyStore, tenant.ID, "k2", "K2", &k1)

		_, err := setup.cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       k1,
		})
		require.NoError(t, err)

		require.Len(t, spy.groups, 1)
		assert.Len(t, spy.groups[0].Jobs, 2, "anchored at k1: k1 -> k2 is two layers")
	})

	t.Run("returns ABORT on an invalid request", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, &rootTopology)

		_, err := setup.cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: "",
			Id:       "",
		})
		require.Error(t, err)
		assert.Empty(t, spy.groups, "invalid requests must not enqueue")
	})

	t.Run("returns NotFound when the key does not exist", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, &rootTopology)
		tenant := createTenant(t, setup.tenantStore)

		_, err := setup.cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       uuid.New().String(),
		})
		require.Error(t, err)
		assert.Empty(t, spy.groups, "an empty hierarchy must not enqueue")
	})
}
