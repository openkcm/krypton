package keyversions_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/inline"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keyversions"
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

type serviceSetup struct {
	db          *sql.DB
	transactor  store.Transactor
	tenantStore store.Tenant
	keyStore    store.Key
	kvStore     store.KeyVersion
	manager     *keyprocessor.Manager
	cli         keyversions.KeyVersionServiceClient
}

func setupServerAndClient(t *testing.T) *serviceSetup {
	t.Helper()
	return setupServerAndClientWithManager(t, nil)
}

func setupServerAndClientWithManager(t *testing.T, mgr *keyprocessor.Manager) *serviceSetup {
	t.Helper()
	return setupWithManagerFactory(t, func(_ context.Context, _ *sql.DB, _ store.Key, _ store.KeyVersion) (*keyprocessor.Manager, error) {
		return mgr, nil
	})
}

func setupWithManagerFactory(t *testing.T, factory func(ctx context.Context, db *sql.DB, ks store.Key, kvs store.KeyVersion) (*keyprocessor.Manager, error)) *serviceSetup {
	t.Helper()
	ctx := t.Context()

	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Agent))

	setup := &serviceSetup{
		db:          db,
		transactor:  storesql.NewTransactor(db),
		tenantStore: storesql.NewTenantStore(db),
		keyStore:    storesql.NewKeyStore(db),
		kvStore:     storesql.NewKeyVersionStore(db),
	}

	mgr, err := factory(ctx, db, setup.keyStore, setup.kvStore)
	require.NoError(t, err)

	setup.manager = mgr

	srv := grpc.NewServer()
	keyversions.RegisterKeyVersionServiceServer(srv, keyversions.NewService(setup.transactor, mgr))

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.Serve(lis); err != nil {
			assert.Fail(t, "keyversion service server error", err)
		}
	}()
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	t.Cleanup(func() {
		srv.GracefulStop()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		conn.Close()
	})

	setup.cli = keyversions.NewKeyVersionServiceClient(conn)
	return setup
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
	return sqlDB
}

func assertErrorDetails(t *testing.T, expCode proto.Code, actErr error) {
	t.Helper()

	st := status.Convert(actErr)
	dts := st.Details()
	require.Len(t, dts, 1, "expected 1 error detail")

	dt, ok := dts[0].(*proto.ErrorDetails)
	require.True(t, ok, "expected error details of type proto.ErrorDetails")
	assert.Equal(t, expCode, dt.GetCode())
}

func createTenant(t *testing.T, s store.Tenant) model.Tenant {
	t.Helper()
	tenant := model.NewTenant("test-tenant-"+uuid.New().String(), nil)
	result, err := s.UpsertTenant(t.Context(), store.UpsertTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return result.Tenant
}

func createKey(t *testing.T, s store.Key, tenantID string, lifecycleState model.KeyLifeCycleState) model.Key {
	t.Helper()
	return createKeyWithKind(t, s, tenantID, "K1", nil, lifecycleState)
}

func createKeyWithKind(t *testing.T, s store.Key, tenantID string, kind string, parentID *string, lifecycleState model.KeyLifeCycleState) model.Key {
	t.Helper()
	key := model.NewKey(tenantID, "test-key-"+uuid.New().String(), kind, parentID, "agent", nil)
	key.LifeCycleState = lifecycleState
	key.KeyProcessingState.Status = model.KeyProcessingCompleted
	require.NoError(t, s.CreateKey(t.Context(), key))
	return key
}

func validUpsertKeyVersionRequest(tenantID, keyID string) *keyversions.UpsertKeyVersionRequest {
	return &keyversions.UpsertKeyVersionRequest{
		TenantId:        tenantID,
		KeyId:           keyID,
		Version:         1,
		Revision:        1,
		ParentId:        uuid.New().String(),
		ParentVersion:   1,
		LifecycleState:  string(model.KeyLifeCycleActive),
		ProcessingState: string(model.KeyVersionUsable),
	}
}

func createKeyVersion(t *testing.T, s store.KeyVersion, tenantID, keyID string) model.KeyVersion {
	t.Helper()
	kv := model.NewKeyVersion(tenantID, keyID, 1, nil, nil)
	result, err := s.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
	require.NoError(t, err)
	return result.KeyVersion
}

// blockKeyVersionUpdates installs a PostgreSQL trigger that rejects all
// UPDATE statements on key_versions, causing updateKeyVersion to fail
// while fetchKeyVersion (SELECT) still works.
func blockKeyVersionUpdates(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := t.Context()

	_, err := db.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION reject_kv_update() RETURNS TRIGGER AS $$
		BEGIN RAISE EXCEPTION 'update blocked by test'; END;
		$$ LANGUAGE plpgsql;

		CREATE TRIGGER block_kv_update BEFORE UPDATE ON key_versions
		FOR EACH ROW EXECUTE FUNCTION reject_kv_update();
	`)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `
			DROP TRIGGER IF EXISTS block_kv_update ON key_versions;
			DROP FUNCTION IF EXISTS reject_kv_update();
		`)
	})
}

// blockKeyVersionInserts installs a PostgreSQL trigger that rejects all
// INSERT statements on key_versions, causing createKeyVersion to fail
// while fetchKeyVersion (SELECT) still works and returns "not found".
func blockKeyVersionInserts(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := t.Context()

	_, err := db.ExecContext(ctx, `
		CREATE OR REPLACE FUNCTION reject_kv_insert() RETURNS TRIGGER AS $$
		BEGIN RAISE EXCEPTION 'insert blocked by test'; END;
		$$ LANGUAGE plpgsql;

		CREATE TRIGGER block_kv_insert BEFORE INSERT ON key_versions
		FOR EACH ROW EXECUTE FUNCTION reject_kv_insert();
	`)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `
			DROP TRIGGER IF EXISTS block_kv_insert ON key_versions;
			DROP FUNCTION IF EXISTS reject_kv_insert();
		`)
	})
}

// renameKeyVersionsTable renames the key_versions table so that any
// query against it fails with a DB error, while other tables remain intact.
func renameKeyVersionsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), "ALTER TABLE key_versions RENAME TO key_versions_hidden")
	require.NoError(t, err)
}

// renameKeysTable renames the keys table so that any query against it
// fails with a DB error, while other tables (e.g. tenants) remain intact.
func renameKeysTable(t *testing.T, db *sql.DB) {
	t.Helper()
	// drop key_versions first because it has a FK to keys
	_, err := db.ExecContext(t.Context(), "ALTER TABLE key_versions RENAME TO key_versions_hidden")
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "ALTER TABLE keys RENAME TO keys_hidden")
	require.NoError(t, err)
}

// renameTenantTable renames the tenants table so that any query against it
// fails with a DB error, while validation (which runs before DB access) still passes.
func renameTenantTable(t *testing.T, db *sql.DB) {
	t.Helper()
	// rename in FK dependency order: key_versions -> keys -> tenants
	_, err := db.ExecContext(t.Context(), "ALTER TABLE key_versions RENAME TO key_versions_hidden")
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "ALTER TABLE keys RENAME TO keys_hidden")
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), "ALTER TABLE tenants RENAME TO tenants_hidden")
	require.NoError(t, err)
}

func newTestCryptorSpec() *cryptorprovider.Spec {
	return &cryptorprovider.Spec{
		Name:   "test-cryptor",
		Type:   aes256gcm.TypeAES256GCM,
		Config: &aes256gcm.Config{},
	}
}

func newTestVaultSpec() *vaultprovider.Spec {
	return &vaultprovider.Spec{
		Name: "test-vault",
		Type: sqlitevault.TypeUnsafeMemory,
	}
}

func testHierarchy() spec.KeyHierarchy {
	return spec.KeyHierarchy{
		Name: "test-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
		},
	}
}

// newTestRootManager builds a RootManager backed by the test DB and an
// in-memory vault, allowing the static-secret provider. It is the sealer for
// the root (K0) key.
func newTestRootManager(t *testing.T, db *sql.DB) *keyprocessor.RootManager {
	t.Helper()
	rm, err := keyprocessor.NewRootManager(t.Context(), keyprocessor.RootManagerConfig{
		Transactor: storesql.NewTransactor(db),
		RootKey: spec.RootKeySpec{
			AllowedProviders: []sealer.Type{staticsecret.TypeStaticSecret},
			Vault:            vaultprovider.Spec{Name: "root-vault", Type: sqlitevault.TypeUnsafeMemory},
		},
	})
	require.NoError(t, err)
	return rm
}

// newInlineStaticSecretSpec returns a valid static-secret sealer spec backed by
// an inline 32-byte key, avoiding any external secret source.
func newInlineStaticSecretSpec(t *testing.T) sealerprovider.Spec {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	return sealerprovider.Spec{
		Name: "test-root-sealer",
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

// createActiveRootProvider creates a root (K0) key in pre-activation, binds a
// static-secret provider to it via the RootManager, then activates it so it can
// seal child keys. It returns the created root key.
func createActiveRootProvider(t *testing.T, s store.Key, rm *keyprocessor.RootManager, tenantID string) model.Key {
	t.Helper()
	ctx := t.Context()

	rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "root", nil)
	rootKey.LifeCycleState = model.KeyLifeCyclePreActivation
	rootKey.KeyProcessingState.Status = model.KeyProcessingCompleted
	require.NoError(t, s.CreateKey(ctx, rootKey))

	require.NoError(t, rm.CreateProvider(ctx, keyprocessor.CreateProviderInput{
		TenantID:      tenantID,
		KeyID:         rootKey.ID,
		Spec:          newInlineStaticSecretSpec(t),
		ProviderKeyID: "provider-key-" + uuid.New().String(),
	}))

	require.NoError(t, s.UpdateKeyLifeCycleState(ctx, store.UpdateKeyLifeCycleStateQuery{
		ID:       rootKey.ID,
		TenantID: tenantID,
		NewState: model.KeyLifeCycleActive,
	}))

	return rootKey
}
