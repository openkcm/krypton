package tenants_test

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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	_ "github.com/lib/pq"

	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/tenants"
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

func TestUpsertTenant(t *testing.T) {
	t.Run("should return InvalidArgument when tenant_id is empty", func(t *testing.T) {
		// given
		ctx := t.Context()
		setup := setupServerAndClient(t)

		// when
		_, err := setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:     "",
			Name:   "some-name",
			Labels: map[string]string{},
		})

		// then
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return InvalidArgument when name is empty", func(t *testing.T) {
		// given
		ctx := t.Context()
		setup := setupServerAndClient(t)

		// when
		_, err := setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:     uuid.New().String(),
			Name:   "",
			Labels: map[string]string{},
		})

		// then
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should create a new tenant when it does not exist", func(t *testing.T) {
		// given
		ctx := t.Context()
		setup := setupServerAndClient(t)
		tenantID := uuid.New().String()

		// when
		res, err := setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:     tenantID,
			Name:   "name",
			Labels: map[string]string{},
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, res)

		actTenant, err := setup.tenantStore.GetTenant(ctx, store.GetTenantQuery{ID: tenantID})
		require.NoError(t, err)
		assert.Equal(t, tenantID, actTenant.Tenant.ID)
		assert.Equal(t, "name", actTenant.Tenant.Name)
		assert.Equal(t, model.Labels{}, actTenant.Tenant.Labels)
	})

	t.Run("should create a new tenant with nil labels", func(t *testing.T) {
		// given
		ctx := t.Context()
		setup := setupServerAndClient(t)
		tenantID := uuid.New().String()

		// when
		res, err := setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:     tenantID,
			Name:   "name",
			Labels: nil,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, res)

		actTenant, err := setup.tenantStore.GetTenant(ctx, store.GetTenantQuery{ID: tenantID})
		require.NoError(t, err)
		assert.Equal(t, tenantID, actTenant.Tenant.ID)
		assert.Equal(t, "name", actTenant.Tenant.Name)
		assert.Equal(t, model.Labels{}, actTenant.Tenant.Labels)
	})

	t.Run("should update an existing tenant", func(t *testing.T) {
		// given
		ctx := t.Context()
		setup := setupServerAndClient(t)
		tenantID := uuid.New().String()

		// when
		res, err := setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:     tenantID,
			Name:   "old-name",
			Labels: nil,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, res)

		// when
		res, err = setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:     tenantID,
			Name:   "new-name",
			Labels: map[string]string{"key": "value"},
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, res)

		actTenant, err := setup.tenantStore.GetTenant(ctx, store.GetTenantQuery{ID: tenantID})
		require.NoError(t, err)
		assert.Equal(t, tenantID, actTenant.Tenant.ID)
		assert.Equal(t, "new-name", actTenant.Tenant.Name)
		assert.Equal(t, model.Labels{"key": "value"}, actTenant.Tenant.Labels)
	})

	t.Run("should be idempotent when upserting with the same data", func(t *testing.T) {
		// given
		ctx := t.Context()
		setup := setupServerAndClient(t)
		tenantID := uuid.New().String()

		req := &tenants.UpsertTenantRequest{
			Id:     tenantID,
			Name:   "idempotent-tenant",
			Labels: map[string]string{"env": "test"},
		}

		// when — first upsert (creates)
		res, err := setup.cli.UpsertTenant(ctx, req)

		// then
		require.NoError(t, err)
		assert.NotNil(t, res)

		// when — second upsert with identical data (updates)
		res, err = setup.cli.UpsertTenant(ctx, req)

		// then
		require.NoError(t, err)
		assert.NotNil(t, res)

		actTenant, err := setup.tenantStore.GetTenant(ctx, store.GetTenantQuery{ID: tenantID})
		require.NoError(t, err)
		assert.Equal(t, tenantID, actTenant.Tenant.ID)
		assert.Equal(t, "idempotent-tenant", actTenant.Tenant.Name)
		assert.Equal(t, model.Labels{"env": "test"}, actTenant.Tenant.Labels)
	})

	t.Run("should clear labels when upserting without labels", func(t *testing.T) {
		// given
		ctx := t.Context()
		setup := setupServerAndClient(t)
		tenantID := uuid.New().String()

		// create with labels
		_, err := setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:     tenantID,
			Name:   "name",
			Labels: map[string]string{"env": "prod"},
		})
		require.NoError(t, err)

		// when — upsert without labels
		_, err = setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:   tenantID,
			Name: "name",
		})

		// then — labels are cleared
		require.NoError(t, err)
		actTenant, err := setup.tenantStore.GetTenant(ctx, store.GetTenantQuery{ID: tenantID})
		require.NoError(t, err)
		assert.Equal(t, model.Labels{}, actTenant.Tenant.Labels)
	})

	t.Run("should return internal error when transaction fails", func(t *testing.T) {
		// given
		ctx := t.Context()
		setup := setupServerAndClient(t)
		tenantID := uuid.New().String()

		// drop tables to force a transaction error
		_, err := setup.db.ExecContext(ctx,
			`DROP TABLE key_versions;
			DROP TABLE keys;
			DROP TABLE tenants;`)
		require.NoError(t, err)

		// when
		_, err = setup.cli.UpsertTenant(ctx, &tenants.UpsertTenantRequest{
			Id:     tenantID,
			Name:   "name",
			Labels: map[string]string{"env": "prod"},
		})

		// then
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
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
	tenantStore store.Tenant
	db          *sql.DB
	cli         tenants.TenantServiceClient
}

func setupServerAndClient(t *testing.T) *serviceSetup {
	t.Helper()
	ctx := t.Context()

	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Agent))

	setup := &serviceSetup{
		tenantStore: storesql.NewTenantStore(db),
		db:          db,
	}

	srv := grpc.NewServer()
	tenants.RegisterTenantServiceServer(srv, tenants.NewTenantService(storesql.NewTransactor(db)))

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.Serve(lis); err != nil {
			assert.Fail(t, "tenant service server error", err)
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

	setup.cli = tenants.NewTenantServiceClient(conn)
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
