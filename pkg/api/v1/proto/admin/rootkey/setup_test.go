package rootkey_test

import (
	"context"
	"database/sql"
	"net"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

type testSetup struct {
	client          rootkey.ServiceClient
	keyStore        store.Key
	keyVersionStore store.KeyVersion
	tenantStore     store.Tenant
}

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
	pgContainer, err := postgres.Run(
		ctx,
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

func createDatabase(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)

	dbName := "test_" + strings.ReplaceAll(uuid.New().String(), "-", "")
	_, err = db.ExecContext(ctx, "CREATE DATABASE "+dbName)
	if err != nil {
		db.Close()
		require.NoError(t, err)
	}
	require.NoError(t, db.Close())

	testConnStr := strings.Replace(pgConnStr, "/postgres?", "/"+dbName+"?", 1)
	testDB, err := sql.Open("postgres", testConnStr)
	require.NoError(t, err)
	require.NoError(t, storesql.Migrate(ctx, testDB, storesql.Root))

	t.Cleanup(func() {
		testDB.Close()
		db, err := sql.Open("postgres", pgConnStr)
		if err == nil {
			_, _ = db.ExecContext(context.Background(), "DROP DATABASE "+dbName)
			db.Close()
		}
	})
	return testDB
}

func setupServerAndClient(t *testing.T, db *sql.DB, allowedProviders ...sealer.Type) *testSetup {
	t.Helper()

	manager, err := keyprocessor.NewRootManager(t.Context(), keyprocessor.RootManagerConfig{
		Transactor: storesql.NewTransactor(db),
		RootKey: spec.RootKeySpec{
			AllowedProviders: allowedProviders,
			Vault: vaultprovider.Spec{
				Name: "root-vault",
				Type: sqlitevault.TypeUnsafeMemory,
			},
		},
	})
	require.NoError(t, err)

	server := grpc.NewServer()
	rootkey.RegisterServiceServer(server, rootkey.NewService(manager))
	listener := bufconn.Listen(1024 * 1024)
	go func() {
		if err := server.Serve(listener); err != nil {
			assert.Fail(t, "rootkey service server error", err)
		}
	}()
	t.Cleanup(server.GracefulStop)

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &testSetup{
		client:          rootkey.NewServiceClient(conn),
		keyStore:        storesql.NewKeyStore(db),
		keyVersionStore: storesql.NewKeyVersionStore(db),
		tenantStore:     storesql.NewTenantStore(db),
	}
}

func createTenant(t *testing.T, tenantStore store.Tenant) model.Tenant {
	t.Helper()
	tenant := model.NewTenant("test-tenant-"+uuid.New().String(), nil)
	result, err := tenantStore.UpsertTenant(t.Context(), store.UpsertTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return result.Tenant
}

func createRootKey(t *testing.T, keyStore store.Key, tenantID string, processingComplete bool) model.Key {
	t.Helper()
	key := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
	require.NoError(t, keyStore.CreateKey(t.Context(), key))
	if processingComplete {
		completeKeyProcessing(t, keyStore, key)
	}
	return key
}

func completeKeyProcessing(t *testing.T, keyStore store.Key, key model.Key) {
	t.Helper()
	require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
		ID:        key.ID,
		TenantID:  key.TenantID,
		NewStatus: model.KeyProcessingCompleted,
	}))
}

func activateKey(t *testing.T, keyStore store.Key, key model.Key) {
	t.Helper()
	require.NoError(t, keyStore.UpdateKeyLifeCycleState(t.Context(), store.UpdateKeyLifeCycleStateQuery{
		ID:       key.ID,
		TenantID: key.TenantID,
		NewState: model.KeyLifeCycleActive,
	}))
}

func validCreateRequest(tenantID, keyID string) *rootkey.CreateProviderRequest {
	return &rootkey.CreateProviderRequest{
		TenantId: tenantID,
		KeyId:    keyID,
		Config: &rootkey.ProviderConfig{Provider: &rootkey.ProviderConfig_StaticSecret{
			StaticSecret: &rootkey.StaticSecretConfig{
				SecretName: "test-sealer",
				Secret:     []byte("0123456789abcdef0123456789abcdef"),
			},
		}},
		Auth: &rootkey.ProviderAuth{Provider: &rootkey.ProviderAuth_StaticSecret{
			StaticSecret: &rootkey.StaticSecretAuth{},
		}},
		ProviderKey: &rootkey.ProviderKey{Provider: &rootkey.ProviderKey_StaticSecret{
			StaticSecret: &rootkey.StaticSecretKey{Id: "provider-key-1"},
		}},
	}
}

func createProvider(t *testing.T, setup *testSetup, tenantID, keyID string) {
	t.Helper()
	_, err := setup.client.CreateProvider(t.Context(), validCreateRequest(tenantID, keyID))
	require.NoError(t, err)
}

func assertRPCError(t *testing.T, err error, wantStatus codes.Code, wantDetail proto.Code) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, wantStatus, status.Code(err))

	details := status.Convert(err).Details()
	require.Len(t, details, 1)
	detail, ok := details[0].(*proto.ErrorDetails)
	require.True(t, ok)
	assert.Equal(t, wantDetail, detail.GetCode())
}
