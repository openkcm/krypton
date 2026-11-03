package keyprocessor_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/inline"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
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
	if err != nil {
		assert.FailNowf(t, "failed to connect to PostgreSQL", "error: %v", err)
	}

	dbName := "test_" + strings.ReplaceAll(uuid.New().String(), "-", "")

	_, err = db.ExecContext(ctx, "CREATE DATABASE "+dbName)
	if err != nil {
		db.Close()
		assert.FailNowf(t, "failed to create test database", "error: %v", err)
	}
	db.Close()

	pgConStr := strings.Replace(pgConnStr, "/postgres?", "/"+dbName+"?", 1)
	sqlDB, err := sql.Open("postgres", pgConStr)
	if err != nil {
		assert.FailNowf(t, "failed to connect to test database", "error: %v", err)
	}

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

func activateKey(t *testing.T, db *sql.DB, key model.Key) {
	t.Helper()
	setKeyLifeCycleState(t, db, key, model.KeyLifeCycleActive)
}

func setKeyLifeCycleState(t *testing.T, db *sql.DB, key model.Key, state model.KeyLifeCycleState) {
	t.Helper()
	keyStore := storesql.NewKeyStore(db)
	require.NoError(t, keyStore.UpdateKeyLifeCycleState(t.Context(), store.UpdateKeyLifeCycleStateQuery{
		ID:       key.ID,
		TenantID: key.TenantID,
		NewState: state,
	}))
}

// completeKeyProcessing marks the key's asynchronous processing as completed,
// which the RootManager requires before mutating a provider binding.
func completeKeyProcessing(t *testing.T, db *sql.DB, key model.Key) {
	t.Helper()
	keyStore := storesql.NewKeyStore(db)
	require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
		ID:        key.ID,
		TenantID:  key.TenantID,
		NewStatus: model.KeyProcessingCompleted,
	}))
}

// newTestRootManager builds a RootManager backed by real stores and an
// in-memory vault, allowing the static-secret provider.
func newTestRootManager(t *testing.T, db *sql.DB) *keyprocessor.RootManager {
	t.Helper()
	return keyprocessor.NewRootManagerWithVault(
		storesql.NewTransactor(db),
		newTestVault(t),
		[]sealer.Type{staticsecret.TypeStaticSecret},
	)
}

// newInlineStaticSecretSpec returns a valid static-secret sealer spec backed by
// an inline 32-byte key, avoiding any external secret source.
func newInlineStaticSecretSpec(t *testing.T) sealerprovider.Spec {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	return sealerprovider.Spec{
		Name: "test-sealer",
		Type: staticsecret.TypeStaticSecret,
		Auth: &staticsecret.Auth{},
		Config: &staticsecret.Config{
			Secret: secretprovider.Spec{
				Type:   inline.Type,
				Config: &inline.Config{Secret: base64.StdEncoding.EncodeToString(key)},
			},
		},
	}
}

// createRootProvider creates a root key, completes its processing, and binds a
// static-secret provider to it, returning the key and provider key id.
func createRootProvider(t *testing.T, db *sql.DB, rm *keyprocessor.RootManager, tenantID string) (model.Key, string) {
	t.Helper()
	keyStore := storesql.NewKeyStore(db)

	rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
	require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
	completeKeyProcessing(t, db, rootKey)

	providerKeyID := "provider-key-" + uuid.New().String()
	require.NoError(t, rm.CreateProvider(t.Context(), keyprocessor.CreateProviderInput{
		TenantID:      tenantID,
		KeyID:         rootKey.ID,
		Spec:          newInlineStaticSecretSpec(t),
		ProviderKeyID: providerKeyID,
	}))

	return rootKey, providerKeyID
}
