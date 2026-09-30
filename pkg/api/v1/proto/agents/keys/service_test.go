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
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
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

// mirrorKey mirrors a K1 key (and its Active K0 parent row) onto the
// agent, standing in for the root→agent UpsertKey mirror that precedes
// activation. The parent K0 row is Active but has NO local key version,
// so activating the child exercises the agent's relaxed version resolver
// while the local sealer (standing in for root's remote sealer) can still
// verify the parent is active. Returns the child key ID.
func mirrorKey(t *testing.T, setup *serviceSetup, tenantID string) string {
	t.Helper()
	ctx := t.Context()

	req := validUpsertRequest(tenantID)

	parentKey := model.Key{
		ID:                 req.GetParentId(),
		Name:               "parent-" + uuid.New().String(),
		TenantID:           tenantID,
		Kind:               "K0",
		ManagedBy:          "root",
		LifeCycleState:     model.KeyLifeCycleActive,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
	}
	require.NoError(t, setup.keyStore.CreateKey(ctx, parentKey))

	_, err := setup.cli.UpsertKey(ctx, req)
	require.NoError(t, err)
	return req.GetKeyId()
}

func TestActivateKey(t *testing.T) {
	ctx := t.Context()

	t.Run("should return InvalidArgument when tenant_id is not a UUID", func(t *testing.T) {
		setup := setupServerAndClient(t)

		_, err := setup.cli.ActivateKey(ctx, &keys.ActivateKeyRequest{
			TenantId: "",
			KeyId:    uuid.New().String(),
		})

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return InvalidArgument when key_id is not a UUID", func(t *testing.T) {
		setup := setupServerAndClient(t)

		_, err := setup.cli.ActivateKey(ctx, &keys.ActivateKeyRequest{
			TenantId: uuid.New().String(),
			KeyId:    "not-a-uuid",
		})

		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should activate a mirrored key without a local parent version", func(t *testing.T) {
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)
		keyID := mirrorKey(t, setup, tenant.ID)

		// No parent key or parent key version exists locally — the agent
		// takes the parent linkage from the request and does not resolve it.
		parentKeyVersion := int32(1)
		_, err := setup.cli.ActivateKey(ctx, &keys.ActivateKeyRequest{
			TenantId:         tenant.ID,
			KeyId:            keyID,
			ParentKeyVersion: &parentKeyVersion,
		})
		require.NoError(t, err)

		got, err := setup.keyStore.GetKeyByID(ctx, keyID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, got.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)

		versions, err := setup.keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenant.ID,
			KeyID:           keyID,
			ProcessingState: model.KeyVersionUsable,
			LifeCycleState:  model.KeyLifeCycleActive,
			Limit:           1,
		})
		require.NoError(t, err)
		require.Len(t, versions.KeyVersions, 1)

		kv := versions.KeyVersions[0]
		assert.Equal(t, 1, kv.Version)
		require.NotNil(t, kv.ParentKeyVersion)
		assert.Equal(t, 1, *kv.ParentKeyVersion)
	})

	t.Run("should reject a rerun of an already active key without retry", func(t *testing.T) {
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)
		keyID := mirrorKey(t, setup, tenant.ID)

		parentKeyVersion := int32(1)
		req := &keys.ActivateKeyRequest{
			TenantId:         tenant.ID,
			KeyId:            keyID,
			ParentKeyVersion: &parentKeyVersion,
		}

		_, err := setup.cli.ActivateKey(ctx, req)
		require.NoError(t, err)

		// A second activation cannot re-transition an Active key: the CAS
		// rejects it as FailedPrecondition/ABORT rather than retrying.
		_, err = setup.cli.ActivateKey(ctx, req)
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should reject activation of a missing key", func(t *testing.T) {
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)

		parentKeyVersion := int32(1)
		_, err := setup.cli.ActivateKey(ctx, &keys.ActivateKeyRequest{
			TenantId:         tenant.ID,
			KeyId:            uuid.New().String(),
			ParentKeyVersion: &parentKeyVersion,
		})

		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})
}
