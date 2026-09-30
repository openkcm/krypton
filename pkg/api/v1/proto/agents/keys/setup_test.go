package keys_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
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
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
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
	transactor      store.Transactor
	tenantStore     store.Tenant
	keyStore        store.Key
	keyVersionStore store.KeyVersion
	cli             keys.KeyServiceClient
}

// defaultTestHierarchy mirrors the K0(root) → K1(kek) → K2(tek) → K3(dek)
// hierarchy used to build the sealing manager for activation tests.
func defaultTestHierarchy() spec.KeyHierarchy {
	return spec.KeyHierarchy{
		Name: "test-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
		},
	}
}

func setupServerAndClient(t *testing.T) *serviceSetup {
	t.Helper()
	ctx := t.Context()

	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Agent))

	setup := &serviceSetup{
		transactor:      storesql.NewTransactor(db),
		tenantStore:     storesql.NewTenantStore(db),
		keyStore:        storesql.NewKeyStore(db),
		keyVersionStore: storesql.NewKeyVersionStore(db),
	}

	// Root sealer secret used to seal agent-managed (K1) key material
	// locally in tests, standing in for the remote root sealer.
	sealerKey := make([]byte, 32)
	_, err := rand.Read(sealerKey)
	require.NoError(t, err)
	envName := "TEST_AGENT_SEALER_KEY"
	t.Setenv(envName, base64.StdEncoding.EncodeToString(sealerKey))

	mgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
		KeyStore:        setup.keyStore,
		KeyVersionStore: setup.keyVersionStore,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			"K0": {
				SealerSpec: &sealerprovider.Spec{
					Name: "test-sealer",
					Type: staticsecret.TypeStaticSecret,
					Config: &staticsecret.Config{
						Secret: secretprovider.Spec{
							Type:   envvar.Type,
							Config: &envvar.Config{Name: envName},
						},
					},
				},
			},
			"K1": {
				CryptorSpec: &cryptorprovider.Spec{
					Name:   "cryptor-k1",
					Type:   aes256gcm.TypeAES256GCM,
					Config: &aes256gcm.Config{},
				},
				VaultSpec: &vaultprovider.Spec{
					Name:   "vault-k1",
					Type:   sqlitevault.TypeUnsafe,
					Config: &sqlitevault.FileConfig{Path: filepath.Join(t.TempDir(), "vault-k1.db")},
				},
			},
			"K2": {
				CryptorSpec: &cryptorprovider.Spec{
					Name:   "cryptor-k2",
					Type:   aes256gcm.TypeAES256GCM,
					Config: &aes256gcm.Config{},
				},
				VaultSpec: &vaultprovider.Spec{
					Name:   "vault-k2",
					Type:   sqlitevault.TypeUnsafe,
					Config: &sqlitevault.FileConfig{Path: filepath.Join(t.TempDir(), "vault-k2.db")},
				},
			},
			"K3": {
				CryptorSpec: &cryptorprovider.Spec{
					Name:   "cryptor-k3",
					Type:   aes256gcm.TypeAES256GCM,
					Config: &aes256gcm.Config{},
				},
				VaultSpec: &vaultprovider.Spec{
					Name:   "vault-k3",
					Type:   sqlitevault.TypeUnsafe,
					Config: &sqlitevault.FileConfig{Path: filepath.Join(t.TempDir(), "vault-k3.db")},
				},
			},
		},
		Hierarchy: defaultTestHierarchy(),
	})
	require.NoError(t, err)

	srv := grpc.NewServer()
	keys.RegisterKeyServiceServer(srv, keys.NewKeyService(setup.transactor, mgr))

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.Serve(lis); err != nil {
			assert.Fail(t, "agent key service server error", err)
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

	setup.cli = keys.NewKeyServiceClient(conn)
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

func validUpsertRequest(tenantID string) *keys.UpsertKeyRequest {
	return &keys.UpsertKeyRequest{
		TenantId:       tenantID,
		KeyId:          uuid.New().String(),
		Kind:           "K1",
		Name:           "test-key-" + uuid.New().String(),
		ParentId:       uuid.New().String(),
		LifecycleState: string(model.KeyLifeCyclePreActivation),
		ManagedBy:      "agent-aws",
		Labels:         map[string]string{"env": "test"},
	}
}
