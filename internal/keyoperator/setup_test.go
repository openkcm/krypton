package keyoperator_test

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/pkg/model"
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

func createDatabase(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err, "connecting to PostgreSQL")

	dbName := "test_" + strings.ReplaceAll(uuid.New().String(), "-", "")

	_, err = db.ExecContext(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err, "creating test database")
	db.Close()

	pgConStr := strings.Replace(pgConnStr, "/postgres?", "/"+dbName+"?", 1)
	sqlDB, err := sql.Open("postgres", pgConStr)
	require.NoError(t, err, "connecting to test database")

	t.Cleanup(func() {
		sqlDB.Close()

		db, err := sql.Open("postgres", pgConnStr)
		if err == nil {
			_, _ = db.ExecContext(context.Background(), "DROP DATABASE "+dbName)
			db.Close()
		}
	})

	require.NoError(t, storesql.Migrate(ctx, sqlDB, storesql.Root))

	return sqlDB
}

func createTenant(t *testing.T, db *sql.DB) string {
	t.Helper()
	tenantStore := storesql.NewTenantStore(db)
	tenant := model.NewTenant("test-tenant-"+uuid.New().String(), nil)
	result, err := tenantStore.UpsertTenant(t.Context(), store.UpsertTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return result.Tenant.ID
}

// seedKey creates a key in the database with the given lifecycle state and
// processing status, returning the seeded key with its generated ID.
func seedKey(
	t *testing.T,
	keyStore store.Key,
	tenantID, name, kind string,
	parentID *string,
	lcs model.KeyLifeCycleState,
	ps model.KeyProcessingStatus,
) model.Key {
	t.Helper()
	ctx := t.Context()
	key := model.NewKey(tenantID, name, kind, parentID, "test-agent", nil)
	require.NoError(t, keyStore.CreateKey(ctx, key))

	if lcs != model.KeyLifeCyclePreActivation {
		require.NoError(t, keyStore.UpdateKeyLifeCycleState(ctx, store.UpdateKeyLifeCycleStateQuery{
			ID: key.ID, TenantID: tenantID, NewState: lcs,
		}))
	}
	if ps != model.KeyProcessingPending {
		require.NoError(t, keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
			ID: key.ID, TenantID: tenantID, NewStatus: ps,
		}))
	}

	key.LifeCycleState = lcs
	key.KeyProcessingState.Status = ps
	return key
}
