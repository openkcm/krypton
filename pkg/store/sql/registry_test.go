package sql_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

var pgConnStr string

func TestMain(m *testing.M) {
	pgCleanup, err := setupPostgres()
	if err != nil {
		os.Exit(1)
	}

	exitCode := m.Run()
	pgCleanup()
	os.Exit(exitCode)
}

func TestRegistryUpsert(t *testing.T) {
	// given
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
	})

	subj, err := storesql.NewRegistrySQL(ctx, db)
	require.NoError(t, err)

	t.Run("should insert new registry", func(t *testing.T) {
		// given

		registry := spec.Registry{
			Name:       "test-registry",
			InstanceID: uuid.New().String(),
			Status:     spec.RegistryStatusHealthy,
		}

		// when
		upsertResult, err := subj.Upsert(ctx, store.UpsertRegistryQuery{
			Registry: registry,
		})

		// then

		assert.NoError(t, err)

		assert.Equal(t, registry.Name, upsertResult.Registry.Name)
		assert.Equal(t, registry.InstanceID, upsertResult.Registry.InstanceID)
		assert.Equal(t, registry.Status, upsertResult.Registry.Status)
		assert.Zero(t, upsertResult.Registry.LastHeartbeat)
		assert.NotZero(t, upsertResult.Registry.CreatedAt)
		assert.NotZero(t, upsertResult.Registry.UpdatedAt)
	})

	t.Run("should update existing registry", func(t *testing.T) {
		// given
		registry := spec.Registry{
			Name:       "test-registry",
			InstanceID: uuid.New().String(),
			Status:     spec.RegistryStatusHealthy,
		}

		upsertResult1, err := subj.Upsert(ctx, store.UpsertRegistryQuery{
			Registry: registry,
		})
		require.NoError(t, err)

		registry.Status = spec.RegistryStatusUnhealthy
		registry.LastHeartbeat = clock.Now()

		// when
		upsertResult2, err := subj.Upsert(ctx, store.UpsertRegistryQuery{
			Registry: registry,
		})

		// then

		assert.NoError(t, err)

		assert.Equal(t, registry.Name, upsertResult2.Registry.Name)
		assert.Equal(t, registry.InstanceID, upsertResult2.Registry.InstanceID)
		assert.Equal(t, registry.Status, upsertResult2.Registry.Status)
		assert.Equal(t, registry.LastHeartbeat, upsertResult2.Registry.LastHeartbeat)
		assert.Equal(t, upsertResult1.Registry.CreatedAt, upsertResult2.Registry.CreatedAt)

		assert.NotZero(t, upsertResult2.Registry.UpdatedAt)
		assert.NotEqual(t, upsertResult1.Registry.UpdatedAt, upsertResult2.Registry.UpdatedAt)
		assert.Greater(t, upsertResult2.Registry.UpdatedAt, upsertResult1.Registry.UpdatedAt)
	})
}

func TestGet(t *testing.T) {
	ctx := t.Context()

	t.Run("should get existing registry", func(t *testing.T) {
		// given
		db, err := sql.Open("postgres", pgConnStr)
		require.NoError(t, err)

		t.Cleanup(func() {
			db.Close()
		})

		subj, err := storesql.NewRegistrySQL(ctx, db)
		require.NoError(t, err)

		registry := spec.Registry{
			Name:       "test-registry",
			InstanceID: uuid.New().String(),
			Status:     spec.RegistryStatusHealthy,
		}

		upsertResult, err := subj.Upsert(ctx, store.UpsertRegistryQuery{
			Registry: registry,
		})
		require.NoError(t, err)

		// when
		getResult, err := subj.Get(ctx, store.GetRegistryQuery{
			Name:       registry.Name,
			InstanceID: registry.InstanceID,
		})

		// then

		assert.NoError(t, err)

		assert.Equal(t, upsertResult.Registry.Name, getResult.Registry.Name)
		assert.Equal(t, upsertResult.Registry.InstanceID, getResult.Registry.InstanceID)
		assert.Equal(t, upsertResult.Registry.Status, getResult.Registry.Status)
		assert.Equal(t, upsertResult.Registry.LastHeartbeat, getResult.Registry.LastHeartbeat)
		assert.Equal(t, upsertResult.Registry.CreatedAt, getResult.Registry.CreatedAt)
		assert.Equal(t, upsertResult.Registry.UpdatedAt, getResult.Registry.UpdatedAt)
	})

	t.Run("should return error if registry not found", func(t *testing.T) {
		// given
		db, err := sql.Open("postgres", pgConnStr)
		require.NoError(t, err)

		t.Cleanup(func() {
			db.Close()
		})

		subj, err := storesql.NewRegistrySQL(ctx, db)
		require.NoError(t, err)

		// when
		getResult, err := subj.Get(ctx, store.GetRegistryQuery{
			Name:       "non-existent-registry",
			InstanceID: uuid.New().String(),
		})

		// then

		assert.ErrorIs(t, err, store.ErrRegistryNotFound)
		assert.Zero(t, getResult.Registry)
	})
}

func setupPostgres() (func(), error) {
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return nil, err
	}
	cleanUp := func() { _ = pgContainer.Terminate(ctx) }

	pgConnStr, err = pgContainer.ConnectionString(ctx, "sslmode=disable")

	return cleanUp, err
}
