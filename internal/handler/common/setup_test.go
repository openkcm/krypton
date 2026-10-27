package common_test

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

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/handler/common"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	agentkeys "github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keyversions"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/tenants"
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

func createKeyVersion(
	t *testing.T,
	kvStore store.KeyVersion,
	tenantID, keyID string,
	version int,
	parentID *string,
	parentKeyVersion *int,
	opts ...func(*model.KeyVersion),
) model.KeyVersion {
	t.Helper()
	kv := model.NewKeyVersion(tenantID, keyID, version, parentID, parentKeyVersion)
	for _, opt := range opts {
		opt(&kv)
	}
	res, err := kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
	require.NoError(t, err)
	return res.KeyVersion
}

func assertKeyState(t *testing.T, kStore store.Key, k model.Key, wantProcessing model.KeyProcessingStatus, wantLifecycle model.KeyLifeCycleState) {
	t.Helper()
	keyID := k.ID
	tenantID := k.TenantID
	key, err := kStore.GetKeyByID(t.Context(), keyID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, wantProcessing, key.KeyProcessingState.Status)
	assert.Equal(t, wantLifecycle, key.LifeCycleState)
}

// applyResponse extracts the *OrbitalResponse from an error and returns the
// resulting task status after applying it to a HandlerResponse.
func applyResponse(t *testing.T, err error) orbital.TaskResponse {
	t.Helper()
	var or *common.OrbitalResponseError
	require.ErrorAs(t, err, &or)

	resp := orbital.ExecuteHandler(t.Context(), orbital.HandlerFunc(
		func(_ context.Context, _ orbital.HandlerRequest, r *orbital.HandlerResponse) {
			_ = or.Apply(r)
		},
	), orbital.TaskRequest{TaskID: uuid.New(), Type: "test"})
	return resp
}

// ---------------------------------------------------------------------------
// Spec factories
// ---------------------------------------------------------------------------

func newTestVaultSpec() *vaultprovider.Spec {
	return &vaultprovider.Spec{Name: "test-vault", Type: sqlitevault.TypeUnsafeMemory}
}

func newTestCryptorSpec() *cryptorprovider.Spec {
	return &cryptorprovider.Spec{Name: "test-cryptor", Type: aes256gcm.TypeAES256GCM, Config: &aes256gcm.Config{}}
}

func newTestSealerSpec(t *testing.T) *sealerprovider.Spec {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	envName := "TEST_SEALER_KEY_" + uuid.New().String()[:8]
	t.Setenv(envName, base64.StdEncoding.EncodeToString(key))

	return &sealerprovider.Spec{
		Name: "test-sealer",
		Type: staticsecret.TypeStaticSecret,
		Config: &staticsecret.Config{
			Secret: secretprovider.Spec{Type: envvar.Type, Config: &envvar.Config{Name: envName}},
		},
	}
}

func newTestBinding(t *testing.T) spec.KeyBinding {
	t.Helper()
	return spec.KeyBinding{
		SealerSpec:  newTestSealerSpec(t),
		CryptorSpec: newTestCryptorSpec(),
		VaultSpec:   newTestVaultSpec(),
	}
}

// ---------------------------------------------------------------------------
// Agent server infrastructure
// ---------------------------------------------------------------------------

func newAgentDB(t *testing.T) *sql.DB {
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

	require.NoError(t, storesql.Migrate(ctx, testDB, storesql.Agent))

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

type agentServer struct {
	listener *bufconn.Listener
	grpcSrv  *grpc.Server
	db       *sql.DB
	keyStore store.Key
	kvStore  store.KeyVersion
}

func startAgentServer(t *testing.T, mgr *keyprocessor.Manager) *agentServer {
	t.Helper()
	db := newAgentDB(t)
	transactor := storesql.NewTransactor(db)

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)

	srv := grpc.NewServer()
	agentkeys.RegisterKeyServiceServer(srv, agentkeys.NewKeyService(transactor))
	tenants.RegisterTenantServiceServer(srv, tenants.NewTenantService(transactor))
	keyversions.RegisterKeyVersionServiceServer(srv, keyversions.NewService(transactor, mgr))

	go func() { _ = srv.Serve(lis) }()

	s := &agentServer{
		listener: lis, grpcSrv: srv, db: db,
		keyStore: storesql.NewKeyStore(db), kvStore: storesql.NewKeyVersionStore(db),
	}
	t.Cleanup(func() { s.grpcSrv.GracefulStop() })
	return s
}

func seedAgentTenant(t *testing.T, db *sql.DB, tenantID string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO tenants (id, name, labels, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`,
		tenantID, "agent-tenant-"+uuid.New().String(), []byte("{}"), int64(1),
	)
	require.NoError(t, err)
}

func newRegistry(t *testing.T, targetName string, srv *agentServer) *grpcconn.Registry {
	t.Helper()
	dialer := func(context.Context, string) (net.Conn, error) { return srv.listener.Dial() }
	reg, err := grpcconn.NewRegistry(
		[]config.ConnectionConfig{{
			Name:    targetName,
			Address: config.Address{Type: config.AddressTypeGRPC, URL: "passthrough:///bufconn"},
		}},
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

func emptyRegistry(t *testing.T) *grpcconn.Registry {
	t.Helper()
	reg, err := grpcconn.NewRegistry(nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

func dropTenantTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `DROP TABLE key_versions`)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `DROP TABLE keys`)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `DROP TABLE tenants`)
	require.NoError(t, err)
}

func dropKeyVersionsTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), `DROP TABLE key_versions`)
	require.NoError(t, err)
}
