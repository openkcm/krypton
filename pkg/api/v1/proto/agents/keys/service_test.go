package keys_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
)

func TestUpsertKey(t *testing.T) {
	ctx := t.Context()

	t.Run("should return InvalidArgument when tenant_id is empty", func(t *testing.T) {
		setup := setupServerAndClient(t)

		req := validUpsertRequest(uuid.New().String())
		req.TenantId = ""

		_, err := setup.cli.UpsertKey(ctx, req)

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return InvalidArgument when parent_id is malformed", func(t *testing.T) {
		setup := setupServerAndClient(t)

		req := validUpsertRequest(uuid.New().String())
		req.ParentId = "not-a-uuid"

		_, err := setup.cli.UpsertKey(ctx, req)

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return InvalidArgument when lifecycle_state is unknown", func(t *testing.T) {
		setup := setupServerAndClient(t)

		req := validUpsertRequest(uuid.New().String())
		req.LifecycleState = "bogus"

		_, err := setup.cli.UpsertKey(ctx, req)

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return FailedPrecondition when tenant does not exist", func(t *testing.T) {
		setup := setupServerAndClient(t)

		req := validUpsertRequest(uuid.New().String())

		_, err := setup.cli.UpsertKey(ctx, req)

		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return FailedPrecondition on identity conflict", func(t *testing.T) {
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)

		req := validUpsertRequest(tenant.ID)

		// Pre-insert a row with the same (tenant, key_id) but a different Name.
		parentID := req.GetParentId()
		existing := model.Key{
			ID:                 req.GetKeyId(),
			Name:               "different-name",
			TenantID:           tenant.ID,
			Kind:               model.KeyKind(req.GetKind()),
			ParentID:           &parentID,
			ManagedBy:          req.GetManagedBy(),
			LifeCycleState:     model.KeyLifeCyclePreActivation,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		}
		require.NoError(t, setup.keyStore.CreateKey(ctx, existing))

		_, err := setup.cli.UpsertKey(ctx, req)

		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
		assert.Contains(t, status.Convert(err).Message(), keyoperator.ErrKeyConflict.Error())
	})

	t.Run("should create a new key", func(t *testing.T) {
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)

		req := validUpsertRequest(tenant.ID)

		_, err := setup.cli.UpsertKey(ctx, req)
		require.NoError(t, err)

		got, err := setup.keyStore.GetKeyByID(ctx, req.GetKeyId(), tenant.ID)
		require.NoError(t, err)

		assert.Equal(t, req.GetKeyId(), got.ID)
		assert.Equal(t, req.GetName(), got.Name)
		assert.Equal(t, model.KeyKind(req.GetKind()), got.Kind)
		assert.Equal(t, req.GetManagedBy(), got.ManagedBy)
		require.NotNil(t, got.ParentID)
		assert.Equal(t, req.GetParentId(), *got.ParentID)
		assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
		assert.Equal(t, "test", got.Labels["env"])
	})

	t.Run("should be idempotent on repeated call with same identity", func(t *testing.T) {
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)

		req := validUpsertRequest(tenant.ID)

		_, err := setup.cli.UpsertKey(ctx, req)
		require.NoError(t, err)

		first, err := setup.keyStore.GetKeyByID(ctx, req.GetKeyId(), tenant.ID)
		require.NoError(t, err)

		_, err = setup.cli.UpsertKey(ctx, req)
		require.NoError(t, err)

		second, err := setup.keyStore.GetKeyByID(ctx, req.GetKeyId(), tenant.ID)
		require.NoError(t, err)

		assert.Equal(t, first.ID, second.ID)
		assert.Equal(t, first.Name, second.Name)
		assert.Equal(t, model.KeyProcessingCompleted, second.KeyProcessingState.Status)
	})
}
