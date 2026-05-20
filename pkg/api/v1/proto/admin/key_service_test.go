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
	"github.com/openkcm/krypton/pkg/model"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// keyHierarchy holds a test key tree with the following structure:
//
//	A(K0)
//	  B(K1)
//	    D(K2)
//	    E(K2)
//	  C(K1)
//	    F(K2)
//	    G(K2)
//	      H(K3)
type keyHierarchy struct {
	tenant model.Tenant
	root   model.Key // A
	b      model.Key
	c      model.Key
	d      model.Key
	e      model.Key
	f      model.Key
	g      model.Key
	h      model.Key
}

func TestAnnounceKey(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, db)

	t.Run("should create key successfully", func(t *testing.T) {
		// given
		cli := setupKeyServerAndClient(t, keyStore)

		// when
		res, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "root",
			Labels:     map[string]string{"env": "prod"},
		})

		// then
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
		// given
		cli := setupKeyServerAndClient(t, keyStore)

		parentRes, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "parent-" + uuid.NewString(),
			TargetName: "root",
		})
		require.NoError(t, err)

		// when
		res, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "child-" + uuid.NewString(),
			ParentId:   parentRes.GetKey().GetId(),
			TargetName: "root",
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, parentRes.GetKey().GetId(), res.GetKey().GetParentId())
		assert.Equal(t, "root", res.GetKey().GetManagedBy())
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))
		tmpKeyStore := storesql.NewKeyStore(tmpDB)

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys")
		require.NoError(t, err)

		cli := setupKeyServerAndClient(t, tmpKeyStore)

		// when
		resp, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   uuid.NewString(),
			Kind:       "K0",
			Name:       "will-fail",
			TargetName: "root",
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
	})
}

func TestGetKeyService(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, db)

	t.Run("should get key successfully", func(t *testing.T) {
		// given
		cli := setupKeyServerAndClient(t, keyStore)

		// when
		created, err := cli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "get-me-" + uuid.NewString(),
			TargetName: "root",
			Labels:     map[string]string{"env": "staging"},
		})

		// then
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
		// given
		cli := setupKeyServerAndClient(t, keyStore)

		// when
		resp, err := cli.GetKey(ctx, &admin.GetKeyRequest{
			Id:       uuid.NewString(),
			TenantId: tenant.ID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))
		tmpKeyStore := storesql.NewKeyStore(tmpDB)

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys")
		require.NoError(t, err)

		cli := setupKeyServerAndClient(t, tmpKeyStore)

		// when
		resp, err := cli.GetKey(ctx, &admin.GetKeyRequest{
			Id:       uuid.NewString(),
			TenantId: uuid.NewString(),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}

func TestGetKeyChain(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))
	keyStore := storesql.NewKeyStore(db)

	tenant := createTenant(t, db)

	ha := createKeyHierarchy(t, keyStore, tenant)

	cli := setupKeyServerAndClient(t, keyStore)

	t.Run("should get keychain successfully for intermediate", func(t *testing.T) {
		// when
		res, err := cli.GetKeyChain(ctx, &admin.GetKeyChainRequest{
			Id:       ha.d.ID,
			TenantId: tenant.ID,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, res.GetKeys(), 3)
		assert.Equal(t, ha.root.ID, res.GetKeys()[0].GetId())
		assert.Equal(t, ha.b.ID, res.GetKeys()[1].GetId())
		assert.Equal(t, ha.d.ID, res.GetKeys()[2].GetId())
	})

	t.Run("should get keychain successfully for leaf node", func(t *testing.T) {
		// when
		res, err := cli.GetKeyChain(ctx, &admin.GetKeyChainRequest{
			Id:       ha.h.ID,
			TenantId: tenant.ID,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, res.GetKeys(), 4)
		assert.Equal(t, ha.root.ID, res.GetKeys()[0].GetId())
		assert.Equal(t, ha.c.ID, res.GetKeys()[1].GetId())
		assert.Equal(t, ha.g.ID, res.GetKeys()[2].GetId())
		assert.Equal(t, ha.h.ID, res.GetKeys()[3].GetId())
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		// when
		res, err := cli.GetKeyChain(ctx, &admin.GetKeyChainRequest{
			Id:       uuid.NewString(),
			TenantId: tenant.ID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))
		tmpKeyStore := storesql.NewKeyStore(tmpDB)

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys")
		require.NoError(t, err)

		cli := setupKeyServerAndClient(t, tmpKeyStore)

		// when
		resp, err := cli.GetKeyChain(ctx, &admin.GetKeyChainRequest{
			Id:       uuid.NewString(),
			TenantId: uuid.NewString(),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}

// createKeyHierarchy sets up a test key hierarchy with 8 keys across 4 levels and returns the created keys for reference in tests.
// keyHierarchy holds a test key tree with the following structure:
//
//	A(K0)
//	  B(K1)
//	    D(K2)
//	    E(K2)
//	  C(K1)
//	    F(K2)
//	    G(K2)
//	      H(K3)
func createKeyHierarchy(t *testing.T, keyStore *storesql.KeyStore, tenant model.Tenant) keyHierarchy {
	t.Helper()
	ctx := t.Context()

	root := model.NewKey(tenant.ID, "A", "K0", nil, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, root))

	b := model.NewKey(tenant.ID, "B", "K1", &root.ID, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, b))

	c := model.NewKey(tenant.ID, "C", "K1", &root.ID, "root", nil)
	require.NoError(t, keyStore.CreateKey(ctx, c))

	d := model.NewKey(tenant.ID, "D", "K2", &b.ID, "agent-aws", nil)
	require.NoError(t, keyStore.CreateKey(ctx, d))

	e := model.NewKey(tenant.ID, "E", "K2", &b.ID, "agent-azure", nil)
	require.NoError(t, keyStore.CreateKey(ctx, e))

	f := model.NewKey(tenant.ID, "F", "K2", &c.ID, "agent-gcp", nil)
	require.NoError(t, keyStore.CreateKey(ctx, f))

	g := model.NewKey(tenant.ID, "G", "K2", &c.ID, "agent-onprem", nil)
	require.NoError(t, keyStore.CreateKey(ctx, g))

	h := model.NewKey(tenant.ID, "H", "K3", &g.ID, "agent-onprem-2", nil)
	require.NoError(t, keyStore.CreateKey(ctx, h))

	return keyHierarchy{
		tenant: tenant,
		root:   root,
		b:      b,
		c:      c,
		d:      d,
		e:      e,
		f:      f,
		g:      g,
		h:      h,
	}
}
