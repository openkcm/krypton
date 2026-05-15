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
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestAnnounceKey(t *testing.T) {
	ctx := t.Context()
	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, db)

	t.Run("should create key successfully", func(t *testing.T) {
		cli := setupKeyServerAndClient(t, keyStore)

		res, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "root",
			Labels:     map[string]string{"env": "prod"},
		})

		assert.NoError(t, err)
		assert.NotEmpty(t, res.GetKey().GetId())
		assert.Equal(t, "K0", res.GetKey().GetKind())
		assert.Equal(t, "root", res.GetKey().GetManagedBy())
		assert.Equal(t, "pre-activation", res.GetKey().GetState())
		assert.Equal(t, tenant.ID, res.GetKey().GetTenantId())
		assert.Equal(t, "prod", res.GetKey().GetLabels()["env"])
		assert.NotZero(t, res.GetKey().GetCreatedAt())
		assert.NotZero(t, res.GetKey().GetUpdatedAt())
	})

	t.Run("should create key with parent", func(t *testing.T) {
		cli := setupKeyServerAndClient(t, keyStore)

		parentRes, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "parent-" + uuid.NewString(),
			TargetName: "root",
		})
		require.NoError(t, err)

		res, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "child-" + uuid.NewString(),
			ParentId:   parentRes.GetKey().GetId(),
			TargetName: "root",
		})

		assert.NoError(t, err)
		assert.Equal(t, parentRes.GetKey().GetId(), res.GetKey().GetParentId())
		assert.Equal(t, "root", res.GetKey().GetManagedBy())
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))
		tmpKeyStore := storesql.NewKeyStore(tmpDB)

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys")
		require.NoError(t, err)

		cli := setupKeyServerAndClient(t, tmpKeyStore)

		resp, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   uuid.NewString(),
			Kind:       "K0",
			Name:       "will-fail",
			TargetName: "root",
		})

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
	})
}

func TestGetKeyService(t *testing.T) {
	ctx := t.Context()
	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, db)

	t.Run("should get key successfully", func(t *testing.T) {
		cli := setupKeyServerAndClient(t, keyStore)

		created, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "get-me-" + uuid.NewString(),
			TargetName: "root",
			Labels:     map[string]string{"env": "staging"},
		})
		require.NoError(t, err)

		res, err := cli.GetKey(ctx, &admin.GetKeyRequest{
			Id:       created.GetKey().GetId(),
			TenantId: tenant.ID,
		})

		assert.NoError(t, err)
		assert.Equal(t, created.GetKey().GetId(), res.GetKey().GetId())
		assert.Equal(t, created.GetKey().GetName(), res.GetKey().GetName())
		assert.Equal(t, "staging", res.GetKey().GetLabels()["env"])
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		cli := setupKeyServerAndClient(t, keyStore)

		resp, err := cli.GetKey(ctx, &admin.GetKeyRequest{
			Id:       uuid.NewString(),
			TenantId: tenant.ID,
		})

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))
		tmpKeyStore := storesql.NewKeyStore(tmpDB)

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys")
		require.NoError(t, err)

		cli := setupKeyServerAndClient(t, tmpKeyStore)

		resp, err := cli.GetKey(ctx, &admin.GetKeyRequest{
			Id:       uuid.NewString(),
			TenantId: uuid.NewString(),
		})

		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}
