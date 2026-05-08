package admin_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestCreateTenant(t *testing.T) {
	// given
	ctx := t.Context()

	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))
	tenantStore := storesql.NewTenantStore(db)

	t.Run("creates tenant successfully", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, tenantStore)
		expName := "tenant-" + uuid.New().String()

		// when
		res, err := cli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name:   expName,
			Labels: map[string]string{"env": "test"},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, expName, res.GetTenant().GetName())
		assert.NotEmpty(t, res.GetTenant().GetId())
		assert.Equal(t, "test", res.GetTenant().GetLabels()["env"])

		actRes, err := tenantStore.GetTenant(ctx, store.GetTenantQuery{
			ID: res.GetTenant().GetId(),
		})
		assert.NoError(t, err)
		assert.Equal(t, res.GetTenant().GetId(), actRes.Tenant.ID)
		assert.Equal(t, expName, actRes.Tenant.Name)
		assert.Equal(t, "test", actRes.Tenant.Labels["env"])
		assert.NotEmpty(t, actRes.Tenant.CreatedAt)
		assert.NotEmpty(t, actRes.Tenant.UpdatedAt)
	})

	t.Run("should return internal error if there is an error in the tenant store", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))
		tenantStore := storesql.NewTenantStore(tmpDB)

		// Drop the tenants table to simulate a database error
		_, err := tmpDB.ExecContext(ctx, "DROP TABLE tenants CASCADE")
		require.NoError(t, err)

		cli := setupServerAndClient(t, tenantStore)

		// when
		resp, err := cli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name:   "tenant-" + uuid.New().String(),
			Labels: map[string]string{"env": "test"},
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())

		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}

func TestGetTenant(t *testing.T) {
	// given
	ctx := t.Context()

	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))
	tenantStore := storesql.NewTenantStore(db)

	t.Run("should get tenant successfully", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, tenantStore)

		createRes, err := cli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name:   "tenant-" + uuid.New().String(),
			Labels: map[string]string{"env": "test"},
		})
		require.NoError(t, err)
		expTenant := createRes.GetTenant()

		// when
		res, err := cli.GetTenant(ctx, &admin.GetTenantRequest{
			Id: expTenant.GetId(),
		})
		actTenant := res.GetTenant()

		// then
		assert.NoError(t, err)
		assert.Equal(t, expTenant.GetId(), actTenant.GetId())
		assert.Equal(t, expTenant.GetName(), actTenant.GetName())
		assert.Equal(t, "test", actTenant.GetLabels()["env"])
	})

	t.Run("should return not found error if tenant does not exist", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, tenantStore)

		// when
		resp, err := cli.GetTenant(ctx, &admin.GetTenantRequest{
			Id: uuid.New().String(),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.NotFound, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error if there is an error in the tenant store", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))
		tenantStore := storesql.NewTenantStore(tmpDB)

		// Drop the tenants table to simulate a database error
		_, err := tmpDB.ExecContext(ctx, "DROP TABLE tenants CASCADE")
		require.NoError(t, err)

		cli := setupServerAndClient(t, tenantStore)

		// when
		resp, err := cli.GetTenant(ctx, &admin.GetTenantRequest{
			Id: uuid.New().String(),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}

func TestListTenants(t *testing.T) {
	// given
	ctx := t.Context()

	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))
	tenantStore := storesql.NewTenantStore(db)

	t.Run("should list tenants successfully", func(t *testing.T) {
		// given
		cli := setupServerAndClient(t, tenantStore)

		names := map[string]struct{}{}
		for range 3 {
			name := "tenant-" + uuid.New().String()
			names[name] = struct{}{}
			_, err := cli.CreateTenant(ctx, &admin.CreateTenantRequest{
				Name:   name,
				Labels: map[string]string{"env": "test"},
			})
			require.NoError(t, err)
		}

		// when
		res, err := cli.ListTenants(ctx, &admin.ListTenantsRequest{})

		// then
		assert.NoError(t, err)
		foundTenant := 0
		for _, tenant := range res.GetTenants() {
			_, ok := names[tenant.GetName()]
			if !ok {
				continue
			}
			foundTenant++
			assert.Equal(t, "test", tenant.GetLabels()["env"])
			assert.NotEmpty(t, tenant.GetId())
		}
		assert.Equal(t, 3, foundTenant)
	})

	t.Run("should return internal error if there is an error in the tenant store", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))
		tenantStore := storesql.NewTenantStore(tmpDB)

		// Drop the tenants table to simulate a database error
		_, err := tmpDB.ExecContext(ctx, "DROP TABLE tenants CASCADE")
		require.NoError(t, err)

		cli := setupServerAndClient(t, tenantStore)

		// when
		resp, err := cli.ListTenants(ctx, &admin.ListTenantsRequest{})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}
