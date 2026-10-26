package common_test

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
	cleanup, err := setupPostgres()
	if err != nil {
		os.Exit(1)
	}
	exitCode := m.Run()
	cleanup()
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
	cleanup := func() { _ = pgContainer.Terminate(ctx) }
	pgConnStr, err = pgContainer.ConnectionString(ctx, "sslmode=disable")
	return cleanup, err
}

func newRootDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	dbName := "test_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	_, err = db.ExecContext(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	connStr := strings.Replace(pgConnStr, "/postgres?", "/"+dbName+"?", 1)
	testDB, err := sql.Open("postgres", connStr)
	require.NoError(t, err)

	require.NoError(t, storesql.Migrate(ctx, testDB, storesql.Root))

	t.Cleanup(func() {
		testDB.Close()
		root, err := sql.Open("postgres", pgConnStr)
		if err == nil {
			_, _ = root.ExecContext(context.Background(), "DROP DATABASE "+dbName)
			root.Close()
		}
	})
	return testDB
}

func createTenant(t *testing.T, db *sql.DB) model.Tenant {
	t.Helper()
	tenantStore := storesql.NewTenantStore(db)
	tenant := model.NewTenant("test-tenant-"+uuid.New().String(), nil)
	res, err := tenantStore.UpsertTenant(t.Context(), store.UpsertTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return res.Tenant
}

func createKey(t *testing.T, kStore store.Key, k model.Key) model.Key {
	t.Helper()
	key := model.NewKey(k.TenantID, "test-key-"+uuid.New().String(), string(k.Kind), k.ParentID, k.ManagedBy, nil)
	if k.LifeCycleState != "" {
		key.LifeCycleState = k.LifeCycleState
	}
	if k.KeyProcessingState.Status != "" {
		key.KeyProcessingState.Status = k.KeyProcessingState.Status
	}
	require.NoError(t, kStore.CreateKey(t.Context(), key))
	return key
}
