package sql_test

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestCreateKey(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)

	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, tenantStore)

	t.Run("should create key without parent", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "root-key", "K0", nil, "root", model.Labels{"env": "prod"})

		err := keyStore.CreateKey(ctx, key)
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		assert.NoError(t, err)
		assert.Equal(t, key.ID, got.ID)
		assert.Equal(t, key.Name, got.Name)
		assert.Equal(t, key.TenantID, got.TenantID)
		assert.Equal(t, key.Kind, got.Kind)
		assert.Nil(t, got.ParentID)
		assert.Equal(t, "root", got.ManagedBy)
		assert.Equal(t, model.KeyStatePreActivation, got.State)
		assert.Equal(t, "prod", got.Labels["env"])
		assert.NotZero(t, got.CreatedAt)
		assert.NotZero(t, got.UpdatedAt)
	})

	t.Run("should create key with parent", func(t *testing.T) {
		parent := model.NewKey(tenant.ID, "parent-key", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, parent))

		key := model.NewKey(tenant.ID, "child-key", "K1", &parent.ID, "root", model.Labels{"team": "security"})

		err := keyStore.CreateKey(ctx, key)
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		assert.NoError(t, err)
		assert.Equal(t, key.ID, got.ID)
		require.NotNil(t, got.ParentID)
		assert.Equal(t, parent.ID, *got.ParentID)
		assert.Equal(t, "security", got.Labels["team"])
	})

	t.Run("should create key with nil labels", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "no-labels-key", "K0", nil, "root", nil)

		err := keyStore.CreateKey(ctx, key)
		assert.NoError(t, err)
	})

	t.Run("should fail with invalid parent reference", func(t *testing.T) {
		badParent := uuid.NewString()
		key := model.NewKey(tenant.ID, "orphan-key", "K1", &badParent, "root", nil)

		err := keyStore.CreateKey(ctx, key)
		assert.Error(t, err)
	})

	t.Run("should fail with invalid tenant reference", func(t *testing.T) {
		key := model.NewKey(uuid.NewString(), "bad-tenant-key", "K0", nil, "root", nil)

		err := keyStore.CreateKey(ctx, key)
		assert.Error(t, err)
	})
}

func TestGetKey(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)

	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, tenantStore)

	t.Run("should get existing key", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "find-me", "K0", nil, "root", model.Labels{"env": "staging"})
		require.NoError(t, keyStore.CreateKey(ctx, key))

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)

		assert.NoError(t, err)
		assert.Equal(t, key.ID, got.ID)
		assert.Equal(t, key.Name, got.Name)
		assert.Equal(t, key.TenantID, got.TenantID)
		assert.Equal(t, key.Kind, got.Kind)
		assert.Nil(t, got.ParentID)
		assert.Equal(t, "root", got.ManagedBy)
		assert.Equal(t, model.KeyStatePreActivation, got.State)
		assert.Equal(t, "staging", got.Labels["env"])
		assert.Equal(t, key.CreatedAt, got.CreatedAt)
		assert.Equal(t, key.UpdatedAt, got.UpdatedAt)
	})

	t.Run("should get key with parent", func(t *testing.T) {
		parent := model.NewKey(tenant.ID, "parent", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, parent))

		child := model.NewKey(tenant.ID, "child", "K1", &parent.ID, "agent-aws", nil)
		require.NoError(t, keyStore.CreateKey(ctx, child))

		got, err := keyStore.GetKeyByID(ctx, child.ID, tenant.ID)

		assert.NoError(t, err)
		require.NotNil(t, got.ParentID)
		assert.Equal(t, parent.ID, *got.ParentID)
		assert.Equal(t, "agent-aws", got.ManagedBy)
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		_, err := keyStore.GetKeyByID(ctx, uuid.NewString(), tenant.ID)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return not found for wrong tenant", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "wrong-tenant-key", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		_, err := keyStore.GetKeyByID(ctx, key.ID, uuid.NewString())
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}

func createTenant(t *testing.T, s *storesql.TenantStore) model.Tenant {
	t.Helper()
	tenant := model.NewTenant("test-tenant-"+uuid.NewString(), nil)
	result, err := s.CreateTenant(t.Context(), store.CreateTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return result.Tenant
}
