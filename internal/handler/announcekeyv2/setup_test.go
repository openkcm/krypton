package announcekeyv2_test

import (
	"context"
	"database/sql"
	"encoding/json/v2"
	"net"
	"os"
	"strings"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/handler/announcekeyv2"
	agentkeys "github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
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

func seedRootTenantAndKey(t *testing.T, db *sql.DB, managedBy string) model.Key {
	t.Helper()
	ctx := t.Context()

	tenantStore := storesql.NewTenantStore(db)
	tenant := model.NewTenant("test-tenant-"+uuid.New().String(), nil)
	tenantRes, err := tenantStore.CreateTenant(ctx, store.CreateTenantQuery{Tenant: tenant})
	require.NoError(t, err)

	keyStore := storesql.NewKeyStore(db)

	// Root DB has a self-FK: keys(parent_id) -> keys(id). Seed a parent
	// first so the child's parent_id is satisfiable.
	parent := model.NewKey(tenantRes.Tenant.ID, "parent-"+uuid.New().String(), "K0", nil, rootName, nil)
	require.NoError(t, keyStore.CreateKey(ctx, parent))

	parentID := parent.ID
	key := model.NewKey(tenantRes.Tenant.ID, "test-key-"+uuid.New().String(), "K0", &parentID, managedBy, nil)
	require.NoError(t, keyStore.CreateKey(ctx, key))

	// Move processing state to InProgress so the ChainTransaction's
	// UpdateKeyState step (FromProcessing=[InProgress]) matches.
	require.NoError(t, keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
		ID:        key.ID,
		TenantID:  key.TenantID,
		NewStatus: model.KeyProcessingInProgress,
		NewJobID:  uuid.NewV7().String(),
	}))
	key.KeyProcessingState.Status = model.KeyProcessingInProgress
	return key
}

func seedAgentTenant(t *testing.T, db *sql.DB, tenantID string) {
	t.Helper()
	_, err := db.ExecContext(t.Context(),
		`INSERT INTO tenants (id, name, labels, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`,
		tenantID, "agent-tenant-"+uuid.New().String(), []byte("{}"), int64(1),
	)
	require.NoError(t, err)
}

type agentServer struct {
	listener *bufconn.Listener
	grpcSrv  *grpc.Server
	db       *sql.DB
	keyStore store.Key
}

func startAgentServer(t *testing.T) *agentServer {
	t.Helper()

	db := newAgentDB(t)
	transactor := storesql.NewTransactor(db)

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)

	srv := grpc.NewServer()
	agentkeys.RegisterKeyServiceServer(srv, agentkeys.NewKeyService(transactor))

	go func() { _ = srv.Serve(lis) }()

	s := &agentServer{
		listener: lis,
		grpcSrv:  srv,
		db:       db,
		keyStore: storesql.NewKeyStore(db),
	}
	t.Cleanup(s.stop)
	return s
}

func (s *agentServer) stop() {
	s.grpcSrv.GracefulStop()
}

func newRegistry(t *testing.T, targetName string, srv *agentServer) *grpcconn.Registry {
	t.Helper()
	dialer := func(context.Context, string) (net.Conn, error) {
		return srv.listener.Dial()
	}
	reg, err := grpcconn.NewRegistry(
		[]config.ConnectionConfig{{
			Name: targetName,
			Address: config.Address{
				Type: config.AddressTypeGRPC,
				URL:  "passthrough:///bufconn",
			},
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

func taskPayload(t *testing.T, key model.Key) []byte {
	t.Helper()
	payload, err := json.Marshal(key)
	require.NoError(t, err)
	return payload
}

func runTask(t *testing.T, h *announcekeyv2.TaskHandler, payload []byte) orbital.TaskResponse {
	t.Helper()
	return orbital.ExecuteHandler(t.Context(), orbital.HandlerFunc(h.Handle), orbital.TaskRequest{
		TaskID: uuid.NewV7(),
		Type:   announcekeyv2.TaskType,
		Data:   payload,
	})
}

type stubKeyGetFailer struct {
	store.Key

	err error
}

func (s *stubKeyGetFailer) GetKeyByID(context.Context, string, string) (*model.Key, error) {
	return nil, s.err
}
