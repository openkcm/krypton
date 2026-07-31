package sql_test

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestCreateKeyVersion(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	require.NoError(t, storesql.Migrate(ctx, db))
	kvStore := storesql.NewKeyVersionStore(db)
	keyStore := storesql.NewKeyStore(db)
	tenantStore := storesql.NewTenantStore(db)

	tenant := createTenant(t, tenantStore)
	key := model.NewKey(tenant.ID, "kv-create-key-"+uuid.NewString(), "K1", nil, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, key))

	t.Run("should create key version without parent", func(t *testing.T) {
		// given
		now := clock.Now()
		kv := model.KeyVersion{
			TenantID:        tenant.ID,
			KeyID:           key.ID,
			Version:         1,
			Revision:        0,
			LifeCycleState:  model.KeyLifeCycleActive,
			ProcessingState: model.KeyVersionUsable,
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		// when
		result, err := kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{KeyVersion: kv})

		// then
		assert.NoError(t, err)
		assert.Equal(t, kv, result.KeyVersion)
	})

	t.Run("should create key version with parent references", func(t *testing.T) {
		// given
		parentKeyID := uuid.NewString()
		parentKeyVersion := 2
		now := clock.Now()
		kv := model.KeyVersion{
			TenantID:         tenant.ID,
			KeyID:            key.ID,
			Version:          2,
			Revision:         0,
			ParentKeyID:      &parentKeyID,
			ParentKeyVersion: &parentKeyVersion,
			LifeCycleState:   model.KeyLifeCycleActive,
			ProcessingState:  model.KeyVersionUsable,
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		// when
		result, err := kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{KeyVersion: kv})

		// then
		assert.NoError(t, err)
		assert.Equal(t, &parentKeyID, result.KeyVersion.ParentKeyID)
		assert.Equal(t, &parentKeyVersion, result.KeyVersion.ParentKeyVersion)
	})

	t.Run("should fail on duplicate composite key", func(t *testing.T) {
		// given
		now := clock.Now()
		kv := model.KeyVersion{
			TenantID:        tenant.ID,
			KeyID:           key.ID,
			Version:         3,
			Revision:        0,
			LifeCycleState:  model.KeyLifeCycleActive,
			ProcessingState: model.KeyVersionUsable,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		_, err := kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{KeyVersion: kv})
		require.NoError(t, err)

		// when
		_, err = kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{KeyVersion: kv})

		// then
		assert.Error(t, err)
	})

	t.Run("should fail with invalid tenant reference", func(t *testing.T) {
		// given
		now := clock.Now()
		kv := model.KeyVersion{
			TenantID:        uuid.NewString(),
			KeyID:           key.ID,
			Version:         1,
			Revision:        0,
			LifeCycleState:  model.KeyLifeCycleActive,
			ProcessingState: model.KeyVersionUsable,
			CreatedAt:       now,
			UpdatedAt:       now,
		}

		// when
		_, err := kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{KeyVersion: kv})

		// then
		assert.Error(t, err)
	})
}

func TestListKeyVersions(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	require.NoError(t, storesql.Migrate(ctx, db))
	kvStore := storesql.NewKeyVersionStore(db)
	keyStore := storesql.NewKeyStore(db)
	tenantStore := storesql.NewTenantStore(db)

	tenant := createTenant(t, tenantStore)
	key := model.NewKey(tenant.ID, "kv-list-key-"+uuid.NewString(), "K1", nil, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, key))

	// seed: version "1" with revisions 0, 1 (usable), 2 (re-wrapping)
	seeds := []struct {
		version         int
		revision        int
		processingState model.KeyVersionProcessingState
		lifeCycleState  model.KeyLifeCycleState
	}{
		{1, 1, model.KeyVersionUsable, model.KeyLifeCycleCompromised},
		{1, 2, model.KeyVersionUsable, model.KeyLifeCyclePreActivation},
		{2, 1, model.KeyVersionReWrapping, model.KeyLifeCycleActive},
		{2, 3, model.KeyVersionReWrapping, model.KeyLifeCycleActive},
	}
	for i, s := range seeds {
		now := clock.Now() + clock.UnixNano(i) // ensure unique timestamps
		kv := model.KeyVersion{
			TenantID:        tenant.ID,
			KeyID:           key.ID,
			Version:         s.version,
			Revision:        s.revision,
			LifeCycleState:  s.lifeCycleState,
			ProcessingState: s.processingState,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		_, err := kvStore.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{KeyVersion: kv})
		require.NoError(t, err)
	}

	t.Run("should list all revisions for a key version", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
			Version:  1,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, result.KeyVersions, 2)
	})

	t.Run("should filter by processing state", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenant.ID,
			KeyID:           key.ID,
			Version:         1,
			ProcessingState: model.KeyVersionUsable,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, result.KeyVersions, 2)
	})

	t.Run("should order by revision descending", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
			Version:  1,
			OrderBy:  []store.KeyVersionOrder{store.KeyVersionOrderRevisionDesc},
		})

		// then
		assert.NoError(t, err)
		require.Len(t, result.KeyVersions, 2)
		assert.Equal(t, 2, result.KeyVersions[0].Revision)
		assert.Equal(t, 1, result.KeyVersions[1].Revision)
	})

	t.Run("should limit results", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
			Version:  1,
			OrderBy:  []store.KeyVersionOrder{store.KeyVersionOrderRevisionDesc},
			Limit:    1,
		})

		// then
		assert.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		assert.Equal(t, 2, result.KeyVersions[0].Revision)
	})

	t.Run("should resolve highest usable revision", func(t *testing.T) {
		// given
		expRevision := 2

		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenant.ID,
			KeyID:           key.ID,
			Version:         1,
			ProcessingState: model.KeyVersionUsable,
			OrderBy:         []store.KeyVersionOrder{store.KeyVersionOrderRevisionDesc},
			Limit:           1,
		})

		// then
		assert.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		assert.Equal(t, expRevision, result.KeyVersions[0].Revision)
		assert.Equal(t, model.KeyVersionUsable, result.KeyVersions[0].ProcessingState)
	})

	t.Run("should order newest created versions first", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
			OrderBy:  []store.KeyVersionOrder{store.KeyVersionOrderCreatedAtDesc},
		})

		// then
		assert.NoError(t, err)
		require.Len(t, result.KeyVersions, 4)

		time := clock.UnixNano(0)
		for _, kv := range result.KeyVersions[:2] {
			assert.Equal(t, 2, kv.Version)
			if time != 0 {
				assert.Greater(t, time, kv.CreatedAt)
			}
			time = kv.CreatedAt
		}
		for _, kv := range result.KeyVersions[2:] {
			assert.Equal(t, 1, kv.Version)
			if time != 0 {
				assert.Greater(t, time, kv.CreatedAt)
			}
			time = kv.CreatedAt
		}
	})

	t.Run("should resolve latest usable version when no version filter is set", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenant.ID,
			KeyID:           key.ID,
			ProcessingState: model.KeyVersionUsable,
			OrderBy: []store.KeyVersionOrder{
				store.KeyVersionOrderCreatedAtDesc,
				store.KeyVersionOrderRevisionDesc,
			},
			Limit: 1,
		})

		// then
		assert.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		assert.Equal(t, 1, result.KeyVersions[0].Version)
		assert.Equal(t, 2, result.KeyVersions[0].Revision)
		assert.Equal(t, model.KeyVersionUsable, result.KeyVersions[0].ProcessingState)
	})

	t.Run("should resolve highest usable revision of old version when newer version exists", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenant.ID,
			KeyID:           key.ID,
			Version:         1,
			ProcessingState: model.KeyVersionUsable,
			OrderBy:         []store.KeyVersionOrder{store.KeyVersionOrderRevisionDesc},
			Limit:           1,
		})

		// then
		assert.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		assert.Equal(t, 1, result.KeyVersions[0].Version)
		assert.Equal(t, 2, result.KeyVersions[0].Revision)
	})

	t.Run("should return keyversion based on the lifecycle state filter", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:       tenant.ID,
			KeyID:          key.ID,
			LifeCycleState: model.KeyLifeCycleCompromised,
		})

		// then
		assert.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		assert.Equal(t, model.KeyLifeCycleCompromised, result.KeyVersions[0].LifeCycleState)
	})

	t.Run("should get the latest keyversion based on the lifecycle state filter", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:       tenant.ID,
			KeyID:          key.ID,
			LifeCycleState: model.KeyLifeCycleActive,
			OrderBy:        []store.KeyVersionOrder{store.KeyVersionOrderVersionDesc, store.KeyVersionOrderRevisionDesc},
			Limit:          1,
		})

		// then
		assert.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		assert.Equal(t, model.KeyLifeCycleActive, result.KeyVersions[0].LifeCycleState)
		assert.Equal(t, 2, result.KeyVersions[0].Version)
		assert.Equal(t, 3, result.KeyVersions[0].Revision)
	})

	t.Run("should return empty slice when no matches", func(t *testing.T) {
		// when
		result, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
			Version:  99,
		})

		// then
		assert.NoError(t, err)
		assert.Empty(t, result.KeyVersions)
	})
}
