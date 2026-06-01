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

// keyHierarchy holds a test key tree with the following structure:
//
//	A(K0)
//	  B(K1)
//	    D(K2)
//	    E(K2)
//	  C(K1)
//	    F(K2)
//	    G(K2)
//	      H(K3)
type keyHierarchy struct {
	tenant model.Tenant
	root   model.Key // A
	b      model.Key
	c      model.Key
	d      model.Key
	e      model.Key
	f      model.Key
	g      model.Key
	h      model.Key
}

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

func TestGetParentKeys(t *testing.T) {
	// given
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)
	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	h := createKeyHierarchy(t, keyStore, tenantStore)

	t.Run("should get full parent keys for leaf node", func(t *testing.T) {
		// given
		query := store.GetParentKeysQuery{KeyID: h.h.ID, TenantID: h.tenant.ID}

		// when
		result, err := keyStore.GetParentKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 4)
		assert.Equal(t, h.root.ID, result.Keys[0].ID) // A
		assert.Equal(t, h.c.ID, result.Keys[1].ID)    // C
		assert.Equal(t, h.g.ID, result.Keys[2].ID)    // G
		assert.Equal(t, h.h.ID, result.Keys[3].ID)    // H
	})

	t.Run("should get parent keys for intermediate node", func(t *testing.T) {
		// given
		query := store.GetParentKeysQuery{KeyID: h.c.ID, TenantID: h.tenant.ID}

		// when
		result, err := keyStore.GetParentKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 2)
		assert.Equal(t, h.root.ID, result.Keys[0].ID) // A
		assert.Equal(t, h.c.ID, result.Keys[1].ID)    // C
	})

	t.Run("should get parent keys for second intermediate node", func(t *testing.T) {
		// given
		query := store.GetParentKeysQuery{KeyID: h.e.ID, TenantID: h.tenant.ID}

		// when
		result, err := keyStore.GetParentKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 3)
		assert.Equal(t, h.root.ID, result.Keys[0].ID) // A
		assert.Equal(t, h.b.ID, result.Keys[1].ID)    // B
		assert.Equal(t, h.e.ID, result.Keys[2].ID)    // E
	})

	t.Run("should get parent keys for root node", func(t *testing.T) {
		// given
		query := store.GetParentKeysQuery{KeyID: h.root.ID, TenantID: h.tenant.ID}

		// when
		result, err := keyStore.GetParentKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 1)
		assert.Equal(t, h.root.ID, result.Keys[0].ID) // A
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		// given
		query := store.GetParentKeysQuery{KeyID: uuid.NewString(), TenantID: h.tenant.ID}

		// when
		_, err := keyStore.GetParentKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return not found for wrong tenant", func(t *testing.T) {
		// given
		query := store.GetParentKeysQuery{KeyID: h.h.ID, TenantID: uuid.NewString()}

		// when
		_, err := keyStore.GetParentKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}

func TestGetDescendantKeys(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)
	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	k := createKeyHierarchy(t, keyStore, tenantStore)

	t.Run("should get all key tree for root node", func(t *testing.T) {
		// given
		query := store.GetDescendantKeysQuery{KeyID: k.root.ID, TenantID: k.tenant.ID}

		// when
		result, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		require.NoError(t, err)
		depth := 0
		for layer := range result.KeyTree.IterKeysByLayerAsc() {
			switch depth {
			case 0:
				require.Len(t, layer, 1)                // depth 0: A
				assert.Equal(t, k.root.ID, layer[0].ID) // A
			case 1:
				require.Len(t, layer, 2)             // depth 1: B, C
				assert.Equal(t, k.b.ID, layer[0].ID) // B
				assert.Equal(t, k.c.ID, layer[1].ID) // C
			case 2:
				require.Len(t, layer, 4)             // depth 2: D, E, F, G
				assert.Equal(t, k.d.ID, layer[0].ID) // D
				assert.Equal(t, k.e.ID, layer[1].ID) // E
				assert.Equal(t, k.f.ID, layer[2].ID) // F
				assert.Equal(t, k.g.ID, layer[3].ID) // G
			case 3:
				require.Len(t, layer, 1)             // depth 3: H
				assert.Equal(t, k.h.ID, layer[0].ID) // H
			}
			depth++
		}
		assert.Equal(t, 4, depth) // 4 levels total (depth 0-3)
	})

	t.Run("should get tree for intermediate node", func(t *testing.T) {
		// given
		query := store.GetDescendantKeysQuery{KeyID: k.c.ID, TenantID: k.tenant.ID}

		// when
		result, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		require.NoError(t, err)
		depth := 0
		for layer := range result.KeyTree.IterKeysByLayerAsc() {
			switch depth {
			case 0:
				require.Len(t, layer, 1)             // depth 0: C
				assert.Equal(t, k.c.ID, layer[0].ID) // C
			case 1:
				require.Len(t, layer, 2)             // depth 1: F, G
				assert.Equal(t, k.f.ID, layer[0].ID) // F
				assert.Equal(t, k.g.ID, layer[1].ID) // G
			case 2:
				require.Len(t, layer, 1)             // depth 2: H
				assert.Equal(t, k.h.ID, layer[0].ID) // H
			}
			depth++
		}
		require.Equal(t, 3, depth) // 3 depth levels below C including itself
	})

	t.Run("should get only self for leaf node", func(t *testing.T) {
		// given
		query := store.GetDescendantKeysQuery{KeyID: k.h.ID, TenantID: k.tenant.ID}

		// when
		result, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		require.NoError(t, err)
		depth := 0
		for layer := range result.KeyTree.IterKeysByLayerAsc() {
			switch depth {
			case 0:
				require.Len(t, layer, 1)             // depth 0: H
				assert.Equal(t, k.h.ID, layer[0].ID) // H
			}
			depth++
		}
		require.Equal(t, 1, depth) // 1 depth level below H including itself
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		// given
		query := store.GetDescendantKeysQuery{KeyID: uuid.NewString(), TenantID: k.tenant.ID}

		// when
		_, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return not found for wrong tenant", func(t *testing.T) {
		// given
		query := store.GetDescendantKeysQuery{KeyID: k.root.ID, TenantID: uuid.NewString()}

		// when
		_, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}

// createKeyHierarchy sets up a test key hierarchy with 8 keys across 4 levels and returns the created keys for reference in tests.
// keyHierarchy holds a test key tree with the following structure:
//
//	A(K0)
//	  B(K1)
//	    D(K2)
//	    E(K2)
//	  C(K1)
//	    F(K2)
//	    G(K2)
//	      H(K3)
func createKeyHierarchy(t *testing.T, keyStore *storesql.KeyStore, tenantStore *storesql.TenantStore) keyHierarchy {
	t.Helper()
	ctx := t.Context()

	tenant := createTenant(t, tenantStore)

	root := model.NewKey(tenant.ID, "A", "K0", nil, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, root))

	b := model.NewKey(tenant.ID, "B", "K1", &root.ID, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, b))

	c := model.NewKey(tenant.ID, "C", "K1", &root.ID, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, c))

	d := model.NewKey(tenant.ID, "D", "K2", &b.ID, "agent-aws", nil)
	require.NoError(t, keyStore.CreateKey(ctx, d))

	e := model.NewKey(tenant.ID, "E", "K2", &b.ID, "agent-azure", nil)
	require.NoError(t, keyStore.CreateKey(ctx, e))

	f := model.NewKey(tenant.ID, "F", "K2", &c.ID, "agent-gcp", nil)
	require.NoError(t, keyStore.CreateKey(ctx, f))

	g := model.NewKey(tenant.ID, "G", "K2", &c.ID, "agent-onprem", nil)
	require.NoError(t, keyStore.CreateKey(ctx, g))

	h := model.NewKey(tenant.ID, "H", "K3", &g.ID, "agent-onprem-2", nil)
	require.NoError(t, keyStore.CreateKey(ctx, h))

	return keyHierarchy{
		tenant: tenant,
		root:   root,
		b:      b,
		c:      c,
		d:      d,
		e:      e,
		f:      f,
		g:      g,
		h:      h,
	}
}

func createTenant(t *testing.T, s *storesql.TenantStore) model.Tenant {
	t.Helper()
	tenant := model.NewTenant("test-tenant-"+uuid.NewString(), nil)
	result, err := s.CreateTenant(t.Context(), store.CreateTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return result.Tenant
}
