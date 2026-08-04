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

	"github.com/google/uuid"
	"github.com/openkcm/orbital"
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
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
	"github.com/openkcm/krypton/pkg/validator"
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
	cleanUp := func() { _ = pgContainer.Terminate(ctx) }

	pgConnStr, err = pgContainer.ConnectionString(ctx, "sslmode=disable")

	return cleanUp, err
}

// defaultTestHierarchy mirrors the K0(root) → K1(kek) → K2(tek) → K3(dek)
// hierarchy used by the existing fixture builders below.
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

// defaultTestTopology pairs with defaultTestHierarchy and exposes the
// "agent" segment (K1..K3). The root is configured separately via
// testRootName + testRootSegment, mirroring how RootConfig keeps the
// root's segment outside Topology.Segments in production.
func defaultTestTopology() spec.Topology {
	return spec.Topology{
		Segments: []spec.TopologySegment{
			{Name: testAgentName, Segment: spec.HierarchySegment{StartKind: "K1", EndKind: "K3"}},
		},
	}
}

func rootTestTopology() spec.Topology {
	return spec.Topology{
		Segments: []spec.TopologySegment{
			{Name: testRootName, Segment: spec.HierarchySegment{StartKind: "K1", EndKind: "K3"}},
		},
	}
}

var testRootSegment = spec.HierarchySegment{StartKind: "K0", EndKind: "K0"}

const (
	testRootName  = "root"
	testAgentName = "agent"
)

// setupKeyServerAndClient wires KeyService against the given DB using the
// default test hierarchy and a noop job preparer that assigns deterministic
// job IDs.
func setupKeyServerAndClient(t *testing.T, db *sql.DB) keys.KeyServiceClient {
	t.Helper()
	return setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), &noopJobPreparer{}, nil)
}

func setupKeyServerAndClientWith(t *testing.T, db *sql.DB, hierarchy spec.KeyHierarchy, preparer keys.JobPreparer, topology *spec.Topology) keys.KeyServiceClient {
	t.Helper()

	if topology == nil {
		top := defaultTestTopology()
		topology = &top
	}

	keyStore := storesql.NewKeyStore(db)
	keyVersionStore := storesql.NewKeyVersionStore(db)
	tenantStore := storesql.NewTenantStore(db)
	v := validator.NewValidator(testRootSegment, *topology, hierarchy, tenantStore, keyStore)

	// create root secret
	sealerKey := make([]byte, 32)
	_, err := rand.Read(sealerKey)
	require.NoError(t, err)
	envName := "TEST_KMIP_SEALER_KEY"
	t.Setenv(envName, base64.StdEncoding.EncodeToString(sealerKey))

	// create manager
	mgr, err := keyprocessor.NewManager(t.Context(), keyprocessor.ManagerConfig{
		KeyStore:        keyStore,
		KeyVersionStore: storesql.NewKeyVersionStore(db),
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
	keys.RegisterKeyServiceServer(srv, keys.NewKeyService(testRootName, keyStore, keyVersionStore, v, preparer, mgr))

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.Serve(lis); err != nil {
			assert.Fail(t, "key service server error", err)
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

	return keys.NewKeyServiceClient(conn)
}

func createDatabase(t *testing.T) *sql.DB {
	t.Helper()
	ctx := t.Context()

	db, err := sql.Open("postgres", pgConnStr)
	if err != nil {
		assert.FailNowf(t, "failed to connect to PostgreSQL", "error: %v", err)
	}

	dbName := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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

func createTenant(t *testing.T, db *sql.DB) model.Tenant {
	t.Helper()
	ctx := t.Context()
	tenantStore := storesql.NewTenantStore(db)
	tenant := model.NewTenant("test-tenant-"+uuid.NewString(), nil)
	result, err := tenantStore.CreateTenant(ctx, store.CreateTenantQuery{Tenant: tenant})
	require.NoError(t, err)
	return result.Tenant
}

type noopJobPreparer struct{}

func (*noopJobPreparer) PrepareJob(_ context.Context, job orbital.Job) (orbital.Job, error) {
	if job.ID == uuid.Nil {
		job.ID = uuid.Must(uuid.NewUUID())
	}
	return job, nil
}

// spyJobPreparer records each orbital.Job it sees and behaves like
// noopJobPreparer otherwise.
type spyJobPreparer struct {
	jobs []orbital.Job
}

func (s *spyJobPreparer) PrepareJob(_ context.Context, job orbital.Job) (orbital.Job, error) {
	if job.ID == uuid.Nil {
		job.ID = uuid.Must(uuid.NewUUID())
	}
	s.jobs = append(s.jobs, job)
	return job, nil
}
