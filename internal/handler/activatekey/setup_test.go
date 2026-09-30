package activatekey_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/agentclient"
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
	agentkeys "github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

const testRootName = "root"

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

// newRootDB provisions an isolated root database with migrations applied.
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

// testStores bundles the stores and manager a task handler needs.
type testStores struct {
	transactor      store.Transactor
	keyStore        store.Key
	keyVersionStore store.KeyVersion
	tenantStore     store.Tenant
	manager         *keyprocessor.Manager
}

func testHierarchy() spec.KeyHierarchy {
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

// newStores wires the stores plus a keyprocessor.Manager that can seal K0..K3
// against local sqlite vaults, mirroring pkg/api/v1/proto/admin/keys setup.
func newStores(t *testing.T, db *sql.DB) testStores {
	t.Helper()

	s := testStores{
		transactor:      storesql.NewTransactor(db),
		keyStore:        storesql.NewKeyStore(db),
		keyVersionStore: storesql.NewKeyVersionStore(db),
		tenantStore:     storesql.NewTenantStore(db),
	}

	sealerKey := make([]byte, 32)
	_, err := rand.Read(sealerKey)
	require.NoError(t, err)
	envName := "TEST_ACTIVATE_SEALER_KEY"
	t.Setenv(envName, base64.StdEncoding.EncodeToString(sealerKey))

	vaultSpec := func(name string) *vaultprovider.Spec {
		return &vaultprovider.Spec{
			Name:   name,
			Type:   sqlitevault.TypeUnsafe,
			Config: &sqlitevault.FileConfig{Path: filepath.Join(t.TempDir(), name+".db")},
		}
	}
	cryptorSpec := func(name string) *cryptorprovider.Spec {
		return &cryptorprovider.Spec{
			Name:   name,
			Type:   aes256gcm.TypeAES256GCM,
			Config: &aes256gcm.Config{},
		}
	}

	mgr, err := keyprocessor.NewManager(t.Context(), keyprocessor.ManagerConfig{
		KeyStore:        s.keyStore,
		KeyVersionStore: s.keyVersionStore,
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
			"K1": {CryptorSpec: cryptorSpec("cryptor-k1"), VaultSpec: vaultSpec("vault-k1")},
			"K2": {CryptorSpec: cryptorSpec("cryptor-k2"), VaultSpec: vaultSpec("vault-k2")},
			"K3": {CryptorSpec: cryptorSpec("cryptor-k3"), VaultSpec: vaultSpec("vault-k3")},
		},
		Hierarchy: testHierarchy(),
	})
	require.NoError(t, err)
	s.manager = mgr

	return s
}

func seedTenant(t *testing.T, s store.Tenant) model.Tenant {
	t.Helper()
	tenant := model.NewTenant("test-tenant-"+uuid.New().String(), nil)
	res, err := s.UpsertTenant(t.Context(), store.UpsertTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return res.Tenant
}

// seedKey inserts a pre-activation key whose processing state is Completed,
// the state an announced key is in when it becomes eligible for activation.
func seedKey(t *testing.T, keyStore store.Key, tenantID, name, kind, managedBy string, parentID *string) model.Key {
	t.Helper()
	key := model.NewKey(tenantID, name+"-"+uuid.New().String(), kind, parentID, managedBy, nil)
	require.NoError(t, keyStore.CreateKey(t.Context(), key))
	require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
		ID:        key.ID,
		TenantID:  tenantID,
		NewStatus: model.KeyProcessingCompleted,
		NewJobID:  uuid.NewV7().String(),
	}))
	return key
}

// fakeKeyClient is a stub agentkeys.KeyServiceClient recording the last
// ActivateKey request and returning a canned response/error.
type fakeKeyClient struct {
	activateErr error
	gotActivate *agentkeys.ActivateKeyRequest
}

func (c *fakeKeyClient) UpsertKey(_ context.Context, _ *agentkeys.UpsertKeyRequest, _ ...grpc.CallOption) (*agentkeys.UpsertKeyResponse, error) {
	return &agentkeys.UpsertKeyResponse{}, nil
}

func (c *fakeKeyClient) ActivateKey(_ context.Context, in *agentkeys.ActivateKeyRequest, _ ...grpc.CallOption) (*agentkeys.ActivateKeyResponse, error) {
	c.gotActivate = in
	if c.activateErr != nil {
		return nil, c.activateErr
	}
	return &agentkeys.ActivateKeyResponse{}, nil
}

// fakeProvider is an agentclient.Provider returning a fixed client, or an error
// when clientErr is set.
type fakeProvider struct {
	client    agentkeys.KeyServiceClient
	clientErr error
	gotName   string
}

func (p *fakeProvider) Client(agentName string) (agentkeys.KeyServiceClient, error) {
	p.gotName = agentName
	if p.clientErr != nil {
		return nil, p.clientErr
	}
	return p.client, nil
}

var _ agentclient.Provider = (*fakeProvider)(nil)
