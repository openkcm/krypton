package sql_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/lib/pq"

	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func createFreshDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()

	admin, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	dbName := "test_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	_, err = admin.ExecContext(ctx, "CREATE DATABASE "+dbName)
	require.NoError(t, err)
	admin.Close()

	dsn := strings.Replace(pgConnStr, "/postgres?", "/"+dbName+"?", 1)
	db, err := sql.Open("postgres", dsn)
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
		adm, err := sql.Open("postgres", pgConnStr)
		if err == nil {
			_, _ = adm.ExecContext(context.Background(), "DROP DATABASE "+dbName)
			adm.Close()
		}
	})
	return db
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(t.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)`,
		name).Scan(&exists)
	require.NoError(t, err)
	return exists
}

func TestMigrate_Root(t *testing.T) {
	db := createFreshDB(t)
	ctx := t.Context()

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))

	for _, tbl := range []string{"schema_meta", "tenants", "agent_registrations", "keys", "key_versions"} {
		assert.True(t, tableExists(t, db, tbl), "expected table %q to exist", tbl)
	}

	var node string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT node FROM schema_meta`).Scan(&node))
	assert.Equal(t, "root", node)
}

func TestMigrate_Agent(t *testing.T) {
	db := createFreshDB(t)
	ctx := t.Context()

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Agent))

	for _, tbl := range []string{"schema_meta", "tenants", "keys", "key_versions"} {
		assert.True(t, tableExists(t, db, tbl), "expected table %q to exist", tbl)
	}
	assert.False(t, tableExists(t, db, "agent_registrations"),
		"agent node should not create agent_registrations table")

	var node string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT node FROM schema_meta`).Scan(&node))
	assert.Equal(t, "agent", node)
}

func TestMigrate_Idempotent(t *testing.T) {
	db := createFreshDB(t)
	ctx := t.Context()

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))

	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_meta`).Scan(&count))
	assert.Equal(t, 1, count)
}

func TestMigrate_CrossNodeGuard(t *testing.T) {
	db := createFreshDB(t)
	ctx := t.Context()

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	err := storesql.Migrate(ctx, db, storesql.Agent)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already initialized")
}

func TestMigrate_UnknownNode(t *testing.T) {
	db := createFreshDB(t)
	ctx := t.Context()

	err := storesql.Migrate(ctx, db, storesql.Node("bogus"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown node")
}

func TestMigrate_KeyVersionParentFKEnforced(t *testing.T) {
	db := createFreshDB(t)
	ctx := t.Context()

	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))

	tenantID := uuid.New().String()
	keyID := uuid.New().String()
	bogusParentID := uuid.New().String()

	_, err := db.ExecContext(ctx,
		`INSERT INTO tenants (id, name, created_at, updated_at) VALUES ($1, $2, 0, 0)`,
		tenantID, "t")
	require.NoError(t, err)

	_, err = db.ExecContext(ctx,
		`INSERT INTO keys (id, tenant_id, kind, name, managed_by, life_cycle_state, created_at, updated_at)
		 VALUES ($1, $2, 'k', 'n', 'm', 'active', 0, 0)`,
		keyID, tenantID)
	require.NoError(t, err)

	// Inserting a key_version whose parent (parent_key_id, parent_key_version)
	// does not exist in key_versions must fail via FK.
	_, err = db.ExecContext(ctx,
		`INSERT INTO key_versions
		 (tenant_id, key_id, version, revision, parent_key_id, parent_key_version, life_cycle_state, processing_state, created_at, updated_at)
		 VALUES ($1, $2, 1, 1, $3, 1, 'active', 'pending', 0, 0)`,
		tenantID, keyID, bogusParentID)
	require.Error(t, err, "expected FK violation for missing parent key_version")
}
