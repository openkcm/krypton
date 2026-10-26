package activatekey_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json/v2"
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
	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/handler/activatekey"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	agentkeys "github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keyversions"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/tenants"
	sealergrpc "github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// ---------------------------------------------------------------------------
// Postgres container (shared across all tests in the package)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

func createDatabase(t *testing.T) *sql.DB {
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

func newRootDB(t *testing.T) *sql.DB {
	t.Helper()
	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(t.Context(), db, storesql.Root))
	return db
}

func newAgentDB(t *testing.T) *sql.DB {
	t.Helper()
	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(t.Context(), db, storesql.Agent))
	return db
}

// ---------------------------------------------------------------------------
// Data creation helpers
// ---------------------------------------------------------------------------

func createKey(t *testing.T, db store.Key, k model.Key) model.Key {
	t.Helper()
	key := model.NewKey(k.TenantID, "test-key-"+uuid.New().String(), string(k.Kind), k.ParentID, k.ManagedBy, nil)
	if k.LifeCycleState != "" {
		key.LifeCycleState = k.LifeCycleState
	}
	if k.KeyProcessingState.Status != "" {
		key.KeyProcessingState.Status = k.KeyProcessingState.Status
	}
	require.NoError(t, db.CreateKey(t.Context(), key))
	return key
}

func createTenant(t *testing.T, db *sql.DB) model.Tenant {
	t.Helper()
	tenantStore := storesql.NewTenantStore(db)
	tenant := model.NewTenant("test-tenant-"+uuid.New().String(), nil)
	tenantRes, err := tenantStore.UpsertTenant(t.Context(), store.UpsertTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return tenantRes.Tenant
}

func seedAgentTenant(t *testing.T, db *sql.DB, tenantID string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO tenants (id, name, labels, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`,
		tenantID, "agent-tenant-"+uuid.New().String(), []byte("{}"), int64(1),
	)
	require.NoError(t, err)
}

// parentChain holds a K0 (root) -> K1 (KEK) hierarchy with active/usable key versions.
type parentChain struct {
	key0 model.Key
	kv0  model.KeyVersion
	key1 model.Key
	kv1  model.KeyVersion
}

// createParentChain creates the reusable K0 -> K1 parent hierarchy for tests
// that exercise the upsertRemote code path.
func createParentChain(t *testing.T, kStore store.Key, kvStore store.KeyVersion, tenantID, rootName string) parentChain {
	t.Helper()
	key0 := createKey(t, kStore, model.Key{
		TenantID: tenantID, Kind: "K0", ManagedBy: rootName,
		LifeCycleState:     model.KeyLifeCycleActive,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
	})
	kv0 := createKeyVersion(t, kvStore, tenantID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
		kv.ProcessingState = model.KeyVersionUsable
		kv.LifeCycleState = model.KeyLifeCycleActive
	})
	key1 := createKey(t, kStore, model.Key{
		TenantID: tenantID, Kind: "K1", ParentID: new(key0.ID), ManagedBy: rootName,
		LifeCycleState:     model.KeyLifeCycleActive,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
	})
	kv1 := createKeyVersion(t, kvStore, tenantID, key1.ID, 100, &key0.ID, &kv0.Version, func(kv *model.KeyVersion) {
		kv.ProcessingState = model.KeyVersionUsable
		kv.LifeCycleState = model.KeyLifeCycleActive
	})
	return parentChain{key0: key0, kv0: kv0, key1: key1, kv1: kv1}
}

// createRemoteKey creates a K2 (TEK) key managed by agentName, parented to parentKeyID.
func createRemoteKey(t *testing.T, kStore store.Key, tenantID, parentKeyID, agentName string) model.Key {
	t.Helper()
	return createKey(t, kStore, model.Key{
		TenantID: tenantID, Kind: "K2", ParentID: new(parentKeyID), ManagedBy: agentName,
		LifeCycleState:     model.KeyLifeCycleActive,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
	})
}

func taskDataForKey(t *testing.T, key model.Key) []byte {
	t.Helper()
	b, err := json.Marshal(handler.KeyIdentifier{ID: key.ID, TenantID: key.TenantID})
	require.NoError(t, err)
	return b
}

// ---------------------------------------------------------------------------
// DB manipulation (for error-path tests)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// gRPC server infrastructure
// ---------------------------------------------------------------------------

type agentServer struct {
	listener    *bufconn.Listener
	grpcSrv     *grpc.Server
	db          *sql.DB
	keyStore    store.Key
	kvStore     store.KeyVersion
	tenantStore store.Tenant
}

func (s *agentServer) stop() { s.grpcSrv.GracefulStop() }

// startAgentServer creates a fresh agent DB and starts a gRPC server with
// key, tenant, and key-version services registered.
func startAgentServer(t *testing.T, mgr *keyprocessor.Manager) *agentServer {
	t.Helper()
	return startAgentServerFromDB(t, newAgentDB(t), mgr, nil)
}

// startAgentServerFromDB starts a gRPC server using the provided DB.
// If sealerSvc is non-nil the sealer service is also registered.
func startAgentServerFromDB(t *testing.T, db *sql.DB, mgr *keyprocessor.Manager, sealerSvc sealer.Sealer) *agentServer {
	t.Helper()

	transactor := storesql.NewTransactor(db)

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)

	var opts []grpc.ServerOption
	if sealerSvc != nil {
		opts = append(opts, grpc.StatsHandler(securemem.NewRPCHandler()))
	}

	srv := grpc.NewServer(opts...)
	agentkeys.RegisterKeyServiceServer(srv, agentkeys.NewKeyService(transactor))
	tenants.RegisterTenantServiceServer(srv, tenants.NewTenantService(transactor))
	keyversions.RegisterKeyVersionServiceServer(srv, keyversions.NewService(transactor, mgr))
	if sealerSvc != nil {
		sealergrpc.RegisterServiceServer(srv, sealergrpc.NewSealerService(sealerSvc))
	}

	go func() { _ = srv.Serve(lis) }()

	s := &agentServer{
		listener: lis, grpcSrv: srv, db: db,
		keyStore: storesql.NewKeyStore(db), kvStore: storesql.NewKeyVersionStore(db), tenantStore: storesql.NewTenantStore(db),
	}
	t.Cleanup(s.stop)
	return s
}

// ---------------------------------------------------------------------------
// gRPC registries
// ---------------------------------------------------------------------------

// newRegistry creates a bufconn-backed registry pointing to srv under targetName.
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

// ---------------------------------------------------------------------------
// Task runner
// ---------------------------------------------------------------------------

func runTask(t *testing.T, h *activatekey.TaskHandler, payload []byte) orbital.TaskResponse {
	t.Helper()
	return orbital.ExecuteHandler(t.Context(), orbital.HandlerFunc(h.Handle), orbital.TaskRequest{
		TaskID: uuid.NewV7(),
		Type:   activatekey.TaskType,
		Data:   payload,
	})
}

// ---------------------------------------------------------------------------
// Assertions
// ---------------------------------------------------------------------------

func assertTaskDone(t *testing.T, resp orbital.TaskResponse) {
	t.Helper()
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)
}

func assertTaskFailed(t *testing.T, resp orbital.TaskResponse) {
	t.Helper()
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
}

func assertTaskRetry(t *testing.T, resp orbital.TaskResponse) {
	t.Helper()
	assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
	assert.Positive(t, resp.ReconcileAfterSec)
}

func assertKeyState(t *testing.T, s store.Key, keyID, tenantID string, wantProcessing model.KeyProcessingStatus, wantLifecycle model.KeyLifeCycleState) {
	t.Helper()
	key, err := s.GetKeyByID(t.Context(), keyID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, wantProcessing, key.KeyProcessingState.Status)
	assert.Equal(t, wantLifecycle, key.LifeCycleState)
}

func assertKeyVersionCreated(t *testing.T, s store.KeyVersion, tenantID, keyID string) model.KeyVersion {
	t.Helper()
	res, err := s.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{TenantID: tenantID, KeyID: keyID})
	require.NoError(t, err)
	require.Len(t, res.KeyVersions, 1)
	assert.Equal(t, model.KeyVersionUsable, res.KeyVersions[0].ProcessingState)
	assert.Equal(t, model.KeyLifeCycleActive, res.KeyVersions[0].LifeCycleState)
	return res.KeyVersions[0]
}

// ---------------------------------------------------------------------------
// Spec factories (sealer, cryptor, vault)
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

func newTestSealer(t *testing.T) sealer.Sealer {
	t.Helper()
	s, err := sealerprovider.GetSealer(t.Context(), *newTestSealerSpec(t))
	require.NoError(t, err)
	return s
}
