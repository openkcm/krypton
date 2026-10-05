package sql_test

import (
	"database/sql"
	"encoding/base64"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// keyHierarchy holds a test key tree with 10 keys across 4 levels (K0-K3).
// Each key has a distinct lifecycle state, processing status, managing agent,
// and labels to enable targeted filtering, lifecycle transition, and hierarchy
// traversal tests.
//
// Tree structure (lifecycle state, processing status):
//
//	A (K0, root, active, pending, cloud=gcp)
//	├── Z1 (K1, root, pre-activation, pending, cloud=gcp)
//	├── Z2 (K1, root, pre-activation, completed, cloud=aws1)
//	├── B (K1, root, active, pending, cloud=gcp)
//	│   ├── D (K2, agent-aws, suspended, pending, cloud=aws)
//	│   └── E (K2, agent-azure, pre-activation, in-progress, cloud=azure, environment=prod)
//	└── C (K1, root, pre-activation, completed, cloud=azure)
//	    ├── F (K2, agent-gcp, pre-activation, pending, cloud=aws, environment=prod)
//	    └── G (K2, agent-onprem, pre-activation, pending, cloud=azure)
//	        └── H (K3, agent-onprem-2, pre-activation, pending, cloud=aws)
type keyHierarchy struct {
	tenant model.Tenant
	root   model.Key // A
	z1     model.Key // Z1
	z2     model.Key // Z2
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

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
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
		assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, got.KeyProcessingState.Status)
		assert.Empty(t, got.KeyProcessingState.JobID)
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

	t.Run("should fail with invalid tenant reference", func(t *testing.T) {
		key := model.NewKey(uuid.New().String(), "bad-tenant-key", "K0", nil, "root", nil)

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

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
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
		assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState)
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
		_, err := keyStore.GetKeyByID(ctx, uuid.New().String(), tenant.ID)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return not found for wrong tenant", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "wrong-tenant-key", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		_, err := keyStore.GetKeyByID(ctx, key.ID, uuid.New().String())
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}

func TestUpdateKeyLifeCycleState(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, tenantStore)

	t.Run("should update key life cycle state", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "lifecycle-key", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		err := keyStore.UpdateKeyLifeCycleState(ctx, store.UpdateKeyLifeCycleStateQuery{
			ID: key.ID, TenantID: tenant.ID, NewState: model.KeyLifeCycleActive,
		})
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, got.LifeCycleState)
		assert.Greater(t, got.UpdatedAt, got.CreatedAt)
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		err := keyStore.UpdateKeyLifeCycleState(ctx, store.UpdateKeyLifeCycleStateQuery{
			ID: uuid.New().String(), TenantID: tenant.ID, NewState: model.KeyLifeCycleActive,
		})
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return not found for wrong tenant", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "wrong-tenant-lifecycle", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		err := keyStore.UpdateKeyLifeCycleState(ctx, store.UpdateKeyLifeCycleStateQuery{
			ID: key.ID, TenantID: uuid.New().String(), NewState: model.KeyLifeCycleActive,
		})
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}

func TestUpdateKeyProcessingState(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, tenantStore)

	t.Run("should update key processing state with job id", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "processing-key", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		jobID := uuid.New().String()
		err := keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
			ID: key.ID, TenantID: tenant.ID,
			NewStatus: model.KeyProcessingInProgress,
			NewJobID:  jobID,
		})
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingInProgress, got.KeyProcessingState.Status)
		assert.Equal(t, jobID, got.KeyProcessingState.JobID)
		assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState, "lifecycle state must not be mutated")
	})

	t.Run("should clear job id when empty", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "processing-key-2", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		err := keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
			ID: key.ID, TenantID: tenant.ID,
			NewStatus: model.KeyProcessingFailed,
			NewJobID:  "",
		})
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingFailed, got.KeyProcessingState.Status)
		assert.Empty(t, got.KeyProcessingState.JobID)
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		err := keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
			ID: uuid.New().String(), TenantID: tenant.ID,
			NewStatus: model.KeyProcessingFailed,
		})
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}

func TestCreateKey_DuplicateName(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, tenantStore)

	first := model.NewKey(tenant.ID, "dup-name", "K0", nil, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, first))

	second := model.NewKey(tenant.ID, "dup-name", "K0", nil, "root", nil)
	err = keyStore.CreateKey(ctx, second)
	assert.ErrorIs(t, err, store.ErrKeyInsertConflict)
}

func TestGetKeyByName(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, tenantStore)

	t.Run("should get key by name", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "named-key", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		got, err := keyStore.GetKeyByName(ctx, store.GetKeyByNameQuery{TenantID: tenant.ID, Name: "named-key"})
		require.NoError(t, err)
		assert.Equal(t, key.ID, got.ID)
		assert.Equal(t, "named-key", got.Name)
	})

	t.Run("should return not found for unknown name", func(t *testing.T) {
		_, err := keyStore.GetKeyByName(ctx, store.GetKeyByNameQuery{TenantID: tenant.ID, Name: "missing"})
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return not found for wrong tenant", func(t *testing.T) {
		key := model.NewKey(tenant.ID, "tenant-scoped", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		_, err := keyStore.GetKeyByName(ctx, store.GetKeyByNameQuery{TenantID: uuid.New().String(), Name: "tenant-scoped"})
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
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
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
		query := store.GetParentKeysQuery{KeyID: uuid.New().String(), TenantID: h.tenant.ID}

		// when
		_, err := keyStore.GetParentKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return not found for wrong tenant", func(t *testing.T) {
		// given
		query := store.GetParentKeysQuery{KeyID: h.h.ID, TenantID: uuid.New().String()}

		// when
		_, err := keyStore.GetParentKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}

//nolint:gocyclo
func TestGetDescendantKeys(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
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
				require.Len(t, layer, 4)              // depth 1: Z1, Z2, B, C
				assert.Equal(t, k.z1.ID, layer[0].ID) // Z1
				assert.Equal(t, k.z2.ID, layer[1].ID) // Z2
				assert.Equal(t, k.b.ID, layer[2].ID)  // B
				assert.Equal(t, k.c.ID, layer[3].ID)  // C
			case 2:
				require.Len(t, layer, 4)             // depth 2: D, E, F, G
				assert.Equal(t, k.f.ID, layer[2].ID) // F
				assert.Equal(t, k.d.ID, layer[0].ID) // D
				assert.Equal(t, k.e.ID, layer[1].ID) // E
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
		query := store.GetDescendantKeysQuery{KeyID: uuid.New().String(), TenantID: k.tenant.ID}

		// when
		_, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should return not found for wrong tenant", func(t *testing.T) {
		// given
		query := store.GetDescendantKeysQuery{KeyID: k.root.ID, TenantID: uuid.New().String()}

		// when
		_, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should filter by lifecycle state active and exclude non-matching subtrees", func(t *testing.T) {
		// given – only "active" keys pass: A (active) → B (active).
		// Z1, Z2, C are pre-activation so they and their subtrees are excluded.
		// D (suspended) and E (pre-activation) under B are also excluded.
		query := store.GetDescendantKeysQuery{
			KeyID:          k.root.ID,
			TenantID:       k.tenant.ID,
			LifeCycleState: []model.KeyLifeCycleState{model.KeyLifeCycleActive},
		}

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
				require.Len(t, layer, 1)             // depth 1: B only
				assert.Equal(t, k.b.ID, layer[0].ID) // B
			}
			depth++
		}
		assert.Equal(t, 2, depth) // 2 levels: A, B
	})

	t.Run("should return not found when root does not match lifecycle filter", func(t *testing.T) {
		// given – root A is "active", filter requires "pre-activation" → root excluded → empty result.
		query := store.GetDescendantKeysQuery{
			KeyID:          k.root.ID,
			TenantID:       k.tenant.ID,
			LifeCycleState: []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
		}

		// when
		_, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should filter by multiple lifecycle states and exclude suspended subtree", func(t *testing.T) {
		// given – allow "active" and "pre-activation".
		// All keys pass except D (suspended). D has no children so only D is excluded.
		query := store.GetDescendantKeysQuery{
			KeyID:          k.root.ID,
			TenantID:       k.tenant.ID,
			LifeCycleState: []model.KeyLifeCycleState{model.KeyLifeCycleActive, model.KeyLifeCyclePreActivation},
		}

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
				require.Len(t, layer, 4)              // depth 1: Z1, Z2, B, C
				assert.Equal(t, k.z1.ID, layer[0].ID) // Z1
				assert.Equal(t, k.z2.ID, layer[1].ID) // Z2
				assert.Equal(t, k.b.ID, layer[2].ID)  // B
				assert.Equal(t, k.c.ID, layer[3].ID)  // C
			case 2:
				require.Len(t, layer, 3)             // depth 2: E, F, G (D excluded)
				assert.Equal(t, k.e.ID, layer[0].ID) // E
				assert.Equal(t, k.f.ID, layer[1].ID) // F
				assert.Equal(t, k.g.ID, layer[2].ID) // G
			case 3:
				require.Len(t, layer, 1)             // depth 3: H
				assert.Equal(t, k.h.ID, layer[0].ID) // H
			}
			depth++
		}
		assert.Equal(t, 4, depth) // 4 levels total
	})

	t.Run("should filter by status pending and exclude non-matching subtrees", func(t *testing.T) {
		// given – filter by "pending". Z2 (completed) excluded. C (completed) excluded
		// together with its entire subtree (F, G, H). E (in-progress) excluded.
		// Remaining: A → {Z1, B} → {D}.
		query := store.GetDescendantKeysQuery{
			KeyID:    k.root.ID,
			TenantID: k.tenant.ID,
			Status:   []model.KeyProcessingStatus{model.KeyProcessingPending},
		}

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
				require.Len(t, layer, 2)              // depth 1: Z1, B (Z2 excluded)
				assert.Equal(t, k.z1.ID, layer[0].ID) // Z1
				assert.Equal(t, k.b.ID, layer[1].ID)  // B
			case 2:
				require.Len(t, layer, 1)             // depth 2: D only (E excluded)
				assert.Equal(t, k.d.ID, layer[0].ID) // D
			}
			depth++
		}
		assert.Equal(t, 3, depth) // 3 levels: A, {Z1, B}, {D}
	})

	t.Run("should return not found when no key matches status filter", func(t *testing.T) {
		// given – root A has status "pending", filter requires "completed" → root excluded → empty.
		query := store.GetDescendantKeysQuery{
			KeyID:    k.root.ID,
			TenantID: k.tenant.ID,
			Status:   []model.KeyProcessingStatus{model.KeyProcessingCompleted},
		}

		// when
		_, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should filter by both lifecycle state and status together", func(t *testing.T) {
		// given – filter: active + pending. A (active, pending) ✓, B (active, pending) ✓.
		// Z1, Z2, C are pre-activation → excluded with subtrees. D suspended → excluded. E pre-activation → excluded.
		query := store.GetDescendantKeysQuery{
			KeyID:          k.root.ID,
			TenantID:       k.tenant.ID,
			LifeCycleState: []model.KeyLifeCycleState{model.KeyLifeCycleActive},
			Status:         []model.KeyProcessingStatus{model.KeyProcessingPending},
		}

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
				require.Len(t, layer, 1)             // depth 1: B only
				assert.Equal(t, k.b.ID, layer[0].ID) // B
			}
			depth++
		}
		assert.Equal(t, 2, depth) // 2 levels: A, B
	})

	t.Run("should exclude intermediate node and its entire subtree", func(t *testing.T) {
		// given – filter by "active" starting from B.
		// B (active) ✓. D (suspended) ✗ → excluded. E (pre-activation) ✗ → excluded.
		query := store.GetDescendantKeysQuery{
			KeyID:          k.b.ID,
			TenantID:       k.tenant.ID,
			LifeCycleState: []model.KeyLifeCycleState{model.KeyLifeCycleActive},
		}

		// when
		result, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		require.NoError(t, err)
		depth := 0
		for layer := range result.KeyTree.IterKeysByLayerAsc() {
			switch depth {
			case 0:
				require.Len(t, layer, 1)             // depth 0: B
				assert.Equal(t, k.b.ID, layer[0].ID) // B
			}
			depth++
		}
		assert.Equal(t, 1, depth) // only B itself
	})

	t.Run("should return full tree when filter slices are empty", func(t *testing.T) {
		// given – empty slices behave the same as nil (no filter applied).
		query := store.GetDescendantKeysQuery{
			KeyID:          k.root.ID,
			TenantID:       k.tenant.ID,
			LifeCycleState: []model.KeyLifeCycleState{},
			Status:         []model.KeyProcessingStatus{},
		}

		// when
		result, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		require.NoError(t, err)
		depth := 0
		for range result.KeyTree.IterKeysByLayerAsc() {
			depth++
		}
		assert.Equal(t, 4, depth) // all 4 levels present
	})

	t.Run("should filter by multiple statuses and exclude only in-progress subtree", func(t *testing.T) {
		// given – allow "pending" and "completed". Only E (in-progress) is excluded.
		// All other keys match: A(pending), Z1(pending), Z2(completed), B(pending),
		// C(completed), D(pending), F(pending), G(pending), H(pending).
		query := store.GetDescendantKeysQuery{
			KeyID:    k.root.ID,
			TenantID: k.tenant.ID,
			Status:   []model.KeyProcessingStatus{model.KeyProcessingPending, model.KeyProcessingCompleted},
		}

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
				require.Len(t, layer, 4)              // depth 1: Z1, Z2, B, C
				assert.Equal(t, k.z1.ID, layer[0].ID) // Z1
				assert.Equal(t, k.z2.ID, layer[1].ID) // Z2
				assert.Equal(t, k.b.ID, layer[2].ID)  // B
				assert.Equal(t, k.c.ID, layer[3].ID)  // C
			case 2:
				require.Len(t, layer, 3)             // depth 2: D, F, G (E excluded)
				assert.Equal(t, k.d.ID, layer[0].ID) // D
				assert.Equal(t, k.f.ID, layer[1].ID) // F
				assert.Equal(t, k.g.ID, layer[2].ID) // G
			case 3:
				require.Len(t, layer, 1)             // depth 3: H
				assert.Equal(t, k.h.ID, layer[0].ID) // H
			}
			depth++
		}
		assert.Equal(t, 4, depth) // 4 levels total
	})

	t.Run("should filter by both lifecycle and status excluding keys for different reasons", func(t *testing.T) {
		// given – LifeCycleState=[active, pre-activation], Status=[pending].
		// Z2 excluded by status (completed). C excluded by status (completed) → F, G, H cascading.
		// D excluded by lifecycle (suspended). E excluded by status (in-progress).
		// Remaining: A(active,pending), Z1(pre-act,pending), B(active,pending).
		query := store.GetDescendantKeysQuery{
			KeyID:          k.root.ID,
			TenantID:       k.tenant.ID,
			LifeCycleState: []model.KeyLifeCycleState{model.KeyLifeCycleActive, model.KeyLifeCyclePreActivation},
			Status:         []model.KeyProcessingStatus{model.KeyProcessingPending},
		}

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
				require.Len(t, layer, 2)              // depth 1: Z1, B (Z2 excluded by status, C excluded by status)
				assert.Equal(t, k.z1.ID, layer[0].ID) // Z1
				assert.Equal(t, k.b.ID, layer[1].ID)  // B
			}
			depth++
		}
		assert.Equal(t, 2, depth) // 2 levels: A, {Z1, B}
	})

	t.Run("should return not found when root matches lifecycle but not status", func(t *testing.T) {
		// given – A is (active, pending). Filter requires active + completed.
		// Root matches lifecycle but not status → anchor returns nothing → ErrKeyNotFound.
		query := store.GetDescendantKeysQuery{
			KeyID:          k.root.ID,
			TenantID:       k.tenant.ID,
			LifeCycleState: []model.KeyLifeCycleState{model.KeyLifeCycleActive},
			Status:         []model.KeyProcessingStatus{model.KeyProcessingCompleted},
		}

		// when
		_, err := keyStore.GetDescendantKeys(ctx, query)

		// then
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}

func TestListKeys(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	keyStore := storesql.NewKeyStore(db)

	h := createKeyHierarchy(t, keyStore, tenantStore)

	t.Run("should list all keys in descending order", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{TenantID: h.tenant.ID, IsOrderByCreatedAtAsc: false}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 10)
		assert.Equal(t, h.h.ID, result.Keys[0].ID)    // H
		assert.Equal(t, h.g.ID, result.Keys[1].ID)    // G
		assert.Equal(t, h.f.ID, result.Keys[2].ID)    // F
		assert.Equal(t, h.e.ID, result.Keys[3].ID)    // E
		assert.Equal(t, h.d.ID, result.Keys[4].ID)    // D
		assert.Equal(t, h.c.ID, result.Keys[5].ID)    // C
		assert.Equal(t, h.b.ID, result.Keys[6].ID)    // B
		assert.Equal(t, h.z2.ID, result.Keys[7].ID)   // Z2
		assert.Equal(t, h.z1.ID, result.Keys[8].ID)   // Z1
		assert.Equal(t, h.root.ID, result.Keys[9].ID) // A
	})

	t.Run("should list all keys in ascending order", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{TenantID: h.tenant.ID, IsOrderByCreatedAtAsc: true}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 10)
		assert.Equal(t, h.root.ID, result.Keys[0].ID) // A
		assert.Equal(t, h.z1.ID, result.Keys[1].ID)   // Z1
		assert.Equal(t, h.z2.ID, result.Keys[2].ID)   // Z2
		assert.Equal(t, h.b.ID, result.Keys[3].ID)    // B
		assert.Equal(t, h.c.ID, result.Keys[4].ID)    // C
		assert.Equal(t, h.d.ID, result.Keys[5].ID)    // D
		assert.Equal(t, h.e.ID, result.Keys[6].ID)    // E
		assert.Equal(t, h.f.ID, result.Keys[7].ID)    // F
		assert.Equal(t, h.g.ID, result.Keys[8].ID)    // G
		assert.Equal(t, h.h.ID, result.Keys[9].ID)    // H
	})

	t.Run("pagination", func(t *testing.T) {
		t.Run("should paginate through all pages in descending order", func(t *testing.T) {
			// given
			query := store.ListKeysQuery{TenantID: h.tenant.ID, Limit: 3}

			// when
			result, err := keyStore.ListKeys(ctx, query)

			// then
			require.NoError(t, err)
			require.Len(t, result.Keys, 3)

			assert.Equal(t, h.h.ID, result.Keys[0].ID) // H
			assert.Equal(t, h.g.ID, result.Keys[1].ID) // G
			assert.Equal(t, h.f.ID, result.Keys[2].ID) // F
			assert.NotEmpty(t, result.Cursor)

			query.Cursor = result.Cursor
			result, err = keyStore.ListKeys(ctx, query)
			require.NoError(t, err)
			require.Len(t, result.Keys, 3)
			assert.Equal(t, h.e.ID, result.Keys[0].ID) // E
			assert.Equal(t, h.d.ID, result.Keys[1].ID) // D
			assert.Equal(t, h.c.ID, result.Keys[2].ID) // C
			assert.NotEmpty(t, result.Cursor)

			query.Cursor = result.Cursor
			result, err = keyStore.ListKeys(ctx, query)
			require.NoError(t, err)
			require.Len(t, result.Keys, 3)
			assert.Equal(t, h.b.ID, result.Keys[0].ID)  // B
			assert.Equal(t, h.z2.ID, result.Keys[1].ID) // Z2
			assert.Equal(t, h.z1.ID, result.Keys[2].ID) // Z1
			assert.NotEmpty(t, result.Cursor)

			query.Cursor = result.Cursor
			result, err = keyStore.ListKeys(ctx, query)
			require.NoError(t, err)
			require.Len(t, result.Keys, 1)
			assert.Equal(t, h.root.ID, result.Keys[0].ID) // A
			assert.Empty(t, result.Cursor)
		})

		t.Run("should return empty cursor when limit equals total records", func(t *testing.T) {
			// given
			query := store.ListKeysQuery{TenantID: h.tenant.ID, Limit: 10}

			// when
			result, err := keyStore.ListKeys(ctx, query)

			// then
			require.NoError(t, err)
			require.Len(t, result.Keys, 10)
			assert.Empty(t, result.Cursor)
		})

		t.Run("should return empty cursor when limit exceeds total records", func(t *testing.T) {
			// given
			query := store.ListKeysQuery{TenantID: h.tenant.ID, Limit: 20}

			// when
			result, err := keyStore.ListKeys(ctx, query)

			// then
			require.NoError(t, err)
			require.Len(t, result.Keys, 10)
			assert.Empty(t, result.Cursor)
		})

		t.Run("should return empty cursor when limit is negative as default limit is 50", func(t *testing.T) {
			// given
			query := store.ListKeysQuery{TenantID: h.tenant.ID, Limit: -1}

			// when
			result, err := keyStore.ListKeys(ctx, query)

			// then
			require.NoError(t, err)
			require.Len(t, result.Keys, 10)
			assert.Empty(t, result.Cursor)
		})

		t.Run("should return empty cursor when limit is zero as default limit is 50", func(t *testing.T) {
			// given
			query := store.ListKeysQuery{TenantID: h.tenant.ID, Limit: 0}

			// when
			result, err := keyStore.ListKeys(ctx, query)

			// then
			require.NoError(t, err)
			require.Len(t, result.Keys, 10)
			assert.Empty(t, result.Cursor)
		})

		t.Run("should return error for tampered cursor", func(t *testing.T) {
			// given
			query := store.ListKeysQuery{
				TenantID: h.tenant.ID,
				Cursor:   base64.RawURLEncoding.EncodeToString([]byte("{not json")),
			}

			// when
			_, err := keyStore.ListKeys(ctx, query)

			// then
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid cursor")
		})
	})

	t.Run("should return empty list for tenant with no keys", func(t *testing.T) {
		// given
		tenant := createTenant(t, tenantStore)
		query := store.ListKeysQuery{TenantID: tenant.ID}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
		assert.Empty(t, result.Keys)
	})

	t.Run("should filter by kind", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{TenantID: h.tenant.ID, Kind: "K1"}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 4)
		assert.Equal(t, h.z1.ID, result.Keys[3].ID) // Z1
		assert.Equal(t, h.z2.ID, result.Keys[2].ID) // Z2
		assert.Equal(t, h.b.ID, result.Keys[1].ID)  // B
		assert.Equal(t, h.c.ID, result.Keys[0].ID)  // C
	})

	t.Run("should filter by lifecycle state", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{TenantID: h.tenant.ID, LifeCycleState: model.KeyLifeCycleSuspended}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 1)
		assert.Equal(t, h.d.ID, result.Keys[0].ID) // D
	})

	t.Run("should filter by managing agent", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{TenantID: h.tenant.ID, ManagedBy: "agent-onprem"}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 1)
		assert.Equal(t, h.g.ID, result.Keys[0].ID) // G
	})

	t.Run("should filter by labels", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{TenantID: h.tenant.ID, Labels: model.Labels{"cloud": "aws"}}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 3)
		assert.Equal(t, h.h.ID, result.Keys[0].ID) // H
		assert.Equal(t, h.f.ID, result.Keys[1].ID) // F
		assert.Equal(t, h.d.ID, result.Keys[2].ID) // D
	})

	t.Run("should filter by multiple labels", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{TenantID: h.tenant.ID, Labels: model.Labels{"cloud": "azure", "environment": "prod"}}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 1)
		assert.Equal(t, h.e.ID, result.Keys[0].ID) // E
	})

	t.Run("should filter by name substring", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{TenantID: h.tenant.ID, Name: "a"}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 1)
		assert.Equal(t, h.root.ID, result.Keys[0].ID) // A
	})

	t.Run("should treat % as a literal character in name filter", func(t *testing.T) {
		// given
		tenant := createTenant(t, tenantStore)
		match := model.NewKey(tenant.ID, "50%_off", "K1", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, match))
		// Negative control: without escaping, ILIKE "%%%" matches any name.
		decoy := model.NewKey(tenant.ID, "regular-key", "K1", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, decoy))

		query := store.ListKeysQuery{TenantID: tenant.ID, Name: "%"}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		assert.NoError(t, err)
		assert.Len(t, result.Keys, 1)
		if len(result.Keys) == 1 {
			assert.Equal(t, match.ID, result.Keys[0].ID)
		}
	})

	t.Run("should treat _ as a literal character in name filter", func(t *testing.T) {
		// given
		tenant := createTenant(t, tenantStore)
		match := model.NewKey(tenant.ID, "a_b", "K1", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, match))
		// Negative control: without escaping, "a_b" (ILIKE, case-insensitive) also matches "aXb".
		decoy := model.NewKey(tenant.ID, "aXb", "K1", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, decoy))

		query := store.ListKeysQuery{TenantID: tenant.ID, Name: "a_b"}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		assert.NoError(t, err)
		assert.Len(t, result.Keys, 1)
		if len(result.Keys) == 1 {
			assert.Equal(t, match.ID, result.Keys[0].ID)
		}
	})

	t.Run("should treat \\ as a literal character in name filter", func(t *testing.T) {
		// given
		tenant := createTenant(t, tenantStore)
		match := model.NewKey(tenant.ID, `foo\%bar`, "K1", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, match))
		// Negative control: if user's `\` were not escaped, the user-supplied `%`
		// (correctly escaped by us to `\%`) combined with the user's unescaped `\`
		// would form `\\%` in the pattern. Postgres reads `\\` as a literal `\`
		// and the following `%` as a wildcard, causing a false-positive match on
		// `foo\XXXbar`. Escaping user's `\` to `\\` prevents this.
		decoy := model.NewKey(tenant.ID, `foo\XXXbar`, "K1", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, decoy))

		query := store.ListKeysQuery{TenantID: tenant.ID, Name: `foo\%bar`}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		assert.NoError(t, err)
		assert.Len(t, result.Keys, 1)
		if len(result.Keys) == 1 {
			assert.Equal(t, match.ID, result.Keys[0].ID)
		}
	})

	t.Run("should filter by multiple criteria", func(t *testing.T) {
		// given
		query := store.ListKeysQuery{
			TenantID:       h.tenant.ID,
			Kind:           "K2",
			LifeCycleState: model.KeyLifeCyclePreActivation,
			ManagedBy:      "agent-azure",
			Labels:         model.Labels{"environment": "prod"},
		}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		require.NoError(t, err)
		require.Len(t, result.Keys, 1)
		assert.Equal(t, h.e.ID, result.Keys[0].ID) // E
	})

	t.Run("should return key not found error if there are no matching keys for given filter", func(t *testing.T) {
		// given
		unknownTenantID := uuid.New().String()
		query := store.ListKeysQuery{
			TenantID: unknownTenantID,
		}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		assert.Error(t, err)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
		assert.Empty(t, result.Keys)
	})

	t.Run("should return error for invalid tenant ID format", func(t *testing.T) {
		// given
		notValidUUID := "not-valid-uuid"
		query := store.ListKeysQuery{
			TenantID: notValidUUID,
		}

		// when
		result, err := keyStore.ListKeys(ctx, query)

		// then
		assert.Error(t, err)
		assert.ErrorContains(t, err, "invalid input syntax for type uuid")
		assert.Empty(t, result.Keys)
	})
}

func TestUpdateKeyStates(t *testing.T) {
	// given
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	tenantStore := storesql.NewTenantStore(db)

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, tenantStore)

	t.Run("should update key life cycle and processing state", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))
		assert.Equal(t, model.KeyLifeCyclePreActivation, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, key.KeyProcessingState.Status)

		// when
		err := keyStore.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:         key.ID,
			TenantID:   tenant.ID,
			ToState:    model.KeyLifeCycleCompromised,
			ToStatus:   model.KeyProcessingCompleted,
			FromState:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation, model.KeyLifeCycleActive},
			FromStatus: []model.KeyProcessingStatus{model.KeyProcessingPending, model.KeyProcessingInProgress},
		})

		// then
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
	})

	t.Run("should update when from state guard is not specified", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		// when
		err := keyStore.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:         key.ID,
			TenantID:   tenant.ID,
			ToState:    model.KeyLifeCycleCompromised,
			ToStatus:   model.KeyProcessingCompleted,
			FromStatus: []model.KeyProcessingStatus{model.KeyProcessingPending},
		})

		// then
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
	})

	t.Run("should update when from status guard is not specified", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		// when
		err := keyStore.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:        key.ID,
			TenantID:  tenant.ID,
			ToState:   model.KeyLifeCycleCompromised,
			ToStatus:  model.KeyProcessingCompleted,
			FromState: []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
		})

		// then
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
	})

	t.Run("should update when no guards are specified", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		// when
		err := keyStore.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:       key.ID,
			TenantID: tenant.ID,
			ToState:  model.KeyLifeCycleCompromised,
			ToStatus: model.KeyProcessingCompleted,
		})

		// then
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
	})

	t.Run("should not update when from status guard does not match", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))
		assert.Equal(t, model.KeyLifeCyclePreActivation, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, key.KeyProcessingState.Status)

		// when
		err := keyStore.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:         key.ID,
			TenantID:   tenant.ID,
			ToState:    model.KeyLifeCycleCompromised,
			ToStatus:   model.KeyProcessingCompleted,
			FromState:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
			FromStatus: []model.KeyProcessingStatus{model.KeyProcessingFailed},
		})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, got.KeyProcessingState.Status)
	})

	t.Run("should not update when from state guard does not match", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))
		assert.Equal(t, model.KeyLifeCyclePreActivation, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, key.KeyProcessingState.Status)

		// when
		err := keyStore.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:         key.ID,
			TenantID:   tenant.ID,
			ToState:    model.KeyLifeCycleCompromised,
			ToStatus:   model.KeyProcessingCompleted,
			FromState:  []model.KeyLifeCycleState{model.KeyLifeCycleActive},
			FromStatus: []model.KeyProcessingStatus{model.KeyProcessingPending},
		})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)

		got, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, got.KeyProcessingState.Status)
	})
}

// createKeyHierarchy creates a tenant and inserts 10 keys forming the tree documented on [keyHierarchy].
// Keys are created with varying lifecycle states (active, suspended, pre-activation), processing statuses
// (pending, completed, in-progress), managing agents (root, agent-aws, agent-azure, agent-gcp, agent-onprem,
// agent-onprem-2), and labels (cloud, environment) to support filtering, lifecycle transition, and hierarchy
// traversal tests.
func createKeyHierarchy(t *testing.T, keyStore *storesql.KeyStore, tenantStore *storesql.TenantStore) keyHierarchy {
	t.Helper()
	ctx := t.Context()

	tenant := createTenant(t, tenantStore)

	root := model.NewKey(tenant.ID, "A", "K0", nil, "root", model.Labels{
		"cloud": "gcp",
	})
	root.LifeCycleState = model.KeyLifeCycleActive
	require.NoError(t, keyStore.CreateKey(ctx, root))

	z1 := model.NewKey(tenant.ID, "Z1", "K1", &root.ID, "root", model.Labels{
		"cloud": "gcp",
	})
	require.NoError(t, keyStore.CreateKey(ctx, z1))

	z2 := model.NewKey(tenant.ID, "Z2", "K1", &root.ID, "root", model.Labels{
		"cloud": "aws1",
	})
	z2.KeyProcessingState.Status = model.KeyProcessingCompleted
	require.NoError(t, keyStore.CreateKey(ctx, z2))

	b := model.NewKey(tenant.ID, "B", "K1", &root.ID, "root", model.Labels{
		"cloud": "gcp",
	})
	b.LifeCycleState = model.KeyLifeCycleActive
	require.NoError(t, keyStore.CreateKey(ctx, b))

	c := model.NewKey(tenant.ID, "C", "K1", &root.ID, "root", model.Labels{
		"cloud": "azure",
	})
	c.KeyProcessingState.Status = model.KeyProcessingCompleted
	require.NoError(t, keyStore.CreateKey(ctx, c))

	d := model.NewKey(tenant.ID, "D", "K2", &b.ID, "agent-aws", model.Labels{
		"cloud": "aws",
	})
	d.LifeCycleState = model.KeyLifeCycleSuspended
	require.NoError(t, keyStore.CreateKey(ctx, d))

	e := model.NewKey(tenant.ID, "E", "K2", &b.ID, "agent-azure", model.Labels{
		"cloud":       "azure",
		"environment": "prod",
	})
	e.KeyProcessingState.Status = model.KeyProcessingInProgress
	require.NoError(t, keyStore.CreateKey(ctx, e))

	f := model.NewKey(tenant.ID, "F", "K2", &c.ID, "agent-gcp", model.Labels{
		"cloud":       "aws",
		"environment": "prod",
	})
	require.NoError(t, keyStore.CreateKey(ctx, f))

	g := model.NewKey(tenant.ID, "G", "K2", &c.ID, "agent-onprem", model.Labels{
		"cloud": "azure",
	})
	require.NoError(t, keyStore.CreateKey(ctx, g))

	h := model.NewKey(tenant.ID, "H", "K3", &g.ID, "agent-onprem-2", model.Labels{
		"cloud": "aws",
	})
	require.NoError(t, keyStore.CreateKey(ctx, h))

	return keyHierarchy{
		tenant: tenant,
		root:   root,
		z1:     z1,
		z2:     z2,
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
	tenant := model.NewTenant("test-tenant-"+uuid.New().String(), nil)
	result, err := s.UpsertTenant(t.Context(), store.UpsertTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return result.Tenant
}
