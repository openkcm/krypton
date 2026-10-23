package keyversions_test

import (
	"context"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/agents/keyversions"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestUpsertKeyVersion(t *testing.T) {
	ctx := t.Context()
	// given
	setup := setupServerAndClient(t)

	t.Run("should return InvalidArgument when request is empty", func(t *testing.T) {
		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, &keyversions.UpsertKeyVersionRequest{})

		// then
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return FailedPrecondition when tenant does not exist", func(t *testing.T) {
		// given
		req := validUpsertKeyVersionRequest(uuid.New().String(), uuid.New().String())

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return Internal when fetching tenant causes a DB error", func(t *testing.T) {
		// given
		setup := setupServerAndClient(t)
		renameTenantTable(t, setup.db)
		req := validUpsertKeyVersionRequest(uuid.New().String(), uuid.New().String())

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should return Internal when fetching key causes a DB error", func(t *testing.T) {
		// given
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)
		renameKeysTable(t, setup.db)
		req := validUpsertKeyVersionRequest(tenant.ID, uuid.New().String())

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should return FailedPrecondition when key is not present", func(t *testing.T) {
		// given
		tenant := createTenant(t, setup.tenantStore)
		req := validUpsertKeyVersionRequest(tenant.ID, uuid.New().String())

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return FailedPrecondition when key is not in the right state", func(t *testing.T) {
		// given
		tenant := createTenant(t, setup.tenantStore)
		key := createKey(t, setup.keyStore, tenant.ID, model.KeyLifeCyclePreActivation)
		req := validUpsertKeyVersionRequest(tenant.ID, key.ID)

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return Internal when fetching key version fails", func(t *testing.T) {
		// given
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)
		key := createKey(t, setup.keyStore, tenant.ID, model.KeyLifeCycleActive)
		renameKeyVersionsTable(t, setup.db)
		req := validUpsertKeyVersionRequest(tenant.ID, key.ID)

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should return Internal when updating existing key version fails", func(t *testing.T) {
		// given
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)
		key := createKey(t, setup.keyStore, tenant.ID, model.KeyLifeCycleActive)
		createKeyVersion(t, setup.kvStore, tenant.ID, key.ID)
		blockKeyVersionUpdates(t, setup.db)
		req := validUpsertKeyVersionRequest(tenant.ID, key.ID)

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should update existing key version successfully", func(t *testing.T) {
		// given
		tenant := createTenant(t, setup.tenantStore)
		key := createKey(t, setup.keyStore, tenant.ID, model.KeyLifeCycleActive)
		seeded := createKeyVersion(t, setup.kvStore, tenant.ID, key.ID)
		req := validUpsertKeyVersionRequest(tenant.ID, key.ID)
		req.ProcessingState = string(model.KeyVersionReWrapping)

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.NoError(t, err)
		result, err := setup.kvStore.GetKeyVersion(ctx, store.GetKeyVersionQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
			Version:  int(req.GetVersion()),
			Revision: int(req.GetRevision()),
		})
		require.NoError(t, err)

		kv := result.KeyVersion
		assert.Equal(t, tenant.ID, kv.TenantID)
		assert.Equal(t, key.ID, kv.KeyID)
		assert.Equal(t, int(req.GetVersion()), kv.Version)
		assert.Equal(t, int(req.GetRevision()), kv.Revision)
		assert.Equal(t, seeded.ParentKeyID, kv.ParentKeyID)
		assert.Equal(t, seeded.ParentKeyVersion, kv.ParentKeyVersion)
		assert.Equal(t, seeded.CreatedAt, kv.CreatedAt)
		assert.Equal(t, model.KeyVersionReWrapping, kv.ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, kv.LifeCycleState)
		assert.GreaterOrEqual(t, kv.UpdatedAt, seeded.UpdatedAt)
	})

	t.Run("should be idempotent when upserting with same state", func(t *testing.T) {
		// given
		tenant := createTenant(t, setup.tenantStore)
		key := createKey(t, setup.keyStore, tenant.ID, model.KeyLifeCycleActive)
		createKeyVersion(t, setup.kvStore, tenant.ID, key.ID)
		req := validUpsertKeyVersionRequest(tenant.ID, key.ID)

		// when — send same request twice
		_, err := setup.cli.UpsertKeyVersion(ctx, req)
		require.NoError(t, err)

		_, err = setup.cli.UpsertKeyVersion(ctx, req)

		// then — second call succeeds with no change
		require.NoError(t, err)
		result, err := setup.kvStore.GetKeyVersion(ctx, store.GetKeyVersionQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
			Version:  int(req.GetVersion()),
			Revision: int(req.GetRevision()),
		})
		require.NoError(t, err)
		assert.Equal(t, model.KeyVersionUsable, result.KeyVersion.ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, result.KeyVersion.LifeCycleState)
	})

	t.Run("should return Internal when creating a new key version fails", func(t *testing.T) {
		// given
		setup := setupServerAndClient(t)
		tenant := createTenant(t, setup.tenantStore)
		key := createKey(t, setup.keyStore, tenant.ID, model.KeyLifeCycleActive)
		blockKeyVersionInserts(t, setup.db)
		req := validUpsertKeyVersionRequest(tenant.ID, key.ID)

		// when
		_, err := setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should return Internal when generateAndSealSecret fails", func(t *testing.T) {
		// given
		mgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore:        storesql.NewKeyStore(nil),
			KeyVersionStore: storesql.NewKeyVersionStore(nil),
		})
		require.NoError(t, err)

		setup := setupServerAndClientWithManager(t, mgr)
		tenant := createTenant(t, setup.tenantStore)
		key := createKey(t, setup.keyStore, tenant.ID, model.KeyLifeCycleActive)
		req := validUpsertKeyVersionRequest(tenant.ID, key.ID)

		// when
		_, err = setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should create key version and seal secret successfully", func(t *testing.T) {
		// given
		hierarchy := testHierarchy()
		setup := setupWithManagerFactory(t, func(ctx context.Context, ks store.Key, kvs store.KeyVersion) (*keyprocessor.Manager, error) {
			return keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
				KeyStore:        ks,
				KeyVersionStore: kvs,
				Bindings: map[model.KeyKind]spec.KeyBinding{
					"K0": {SealerSpec: newTestSealerSpec(t)},
					"K1": {CryptorSpec: newTestCryptorSpec(), VaultSpec: newTestVaultSpec()},
				},
				Hierarchy: hierarchy,
			})
		})

		tenant := createTenant(t, setup.tenantStore)
		key0 := createKeyWithKind(t, setup.keyStore, tenant.ID, "K0", nil, model.KeyLifeCycleActive)
		key1 := createKeyWithKind(t, setup.keyStore, tenant.ID, "K1", &key0.ID, model.KeyLifeCycleActive)
		req := validUpsertKeyVersionRequest(tenant.ID, key1.ID)
		req.ParentId = key0.ID
		req.ParentVersion = 1

		// checking that the key version does not exist before the upsert
		_, err := setup.kvStore.GetKeyVersion(ctx, store.GetKeyVersionQuery{
			TenantID: tenant.ID,
			KeyID:    key1.ID,
			Version:  int(req.GetVersion()),
			Revision: int(req.GetRevision()),
		})
		require.ErrorIs(t, err, store.ErrKeyVersionNotFound)

		// when
		_, err = setup.cli.UpsertKeyVersion(ctx, req)

		// then
		require.NoError(t, err)

		result, err := setup.kvStore.GetKeyVersion(ctx, store.GetKeyVersionQuery{
			TenantID: tenant.ID,
			KeyID:    key1.ID,
			Version:  int(req.GetVersion()),
			Revision: int(req.GetRevision()),
		})
		require.NoError(t, err)
		assert.Equal(t, tenant.ID, result.KeyVersion.TenantID)
		assert.Equal(t, key1.ID, result.KeyVersion.KeyID)
		assert.Equal(t, int(req.GetVersion()), result.KeyVersion.Version)
		assert.Equal(t, int(req.GetRevision()), result.KeyVersion.Revision)
		assert.Equal(t, model.KeyLifeCycleState(req.GetLifecycleState()), result.KeyVersion.LifeCycleState)
		assert.Equal(t, model.KeyVersionProcessingState(req.GetProcessingState()), result.KeyVersion.ProcessingState)

		secret, err := setup.manager.ExportSecret(ctx, keyprocessor.ExportSecretRequest{
			TenantID:   tenant.ID,
			KeyID:      key1.ID,
			KeyVersion: int(req.GetVersion()),
		})
		require.NoError(t, err)
		assert.NotNil(t, secret.Data)
		assert.NotEmpty(t, secret.Data.SecureBytes())
		secret.Data.Destroy()
	})

	t.Run("should update key version state without changing the secret", func(t *testing.T) {
		// given
		hierarchy := testHierarchy()
		setup := setupWithManagerFactory(t, func(ctx context.Context, ks store.Key, kvs store.KeyVersion) (*keyprocessor.Manager, error) {
			return keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
				KeyStore:        ks,
				KeyVersionStore: kvs,
				Bindings: map[model.KeyKind]spec.KeyBinding{
					"K0": {SealerSpec: newTestSealerSpec(t)},
					"K1": {CryptorSpec: newTestCryptorSpec(), VaultSpec: newTestVaultSpec()},
				},
				Hierarchy: hierarchy,
			})
		})

		tenant := createTenant(t, setup.tenantStore)
		key0 := createKeyWithKind(t, setup.keyStore, tenant.ID, "K0", nil, model.KeyLifeCycleActive)
		key1 := createKeyWithKind(t, setup.keyStore, tenant.ID, "K1", &key0.ID, model.KeyLifeCycleActive)

		createReq := validUpsertKeyVersionRequest(tenant.ID, key1.ID)
		createReq.ParentId = key0.ID
		createReq.ParentVersion = 1

		_, err := setup.cli.UpsertKeyVersion(ctx, createReq)
		require.NoError(t, err)

		originalSecret, err := setup.manager.ExportSecret(ctx, keyprocessor.ExportSecretRequest{
			TenantID:   tenant.ID,
			KeyID:      key1.ID,
			KeyVersion: int(createReq.GetVersion()),
		})
		require.NoError(t, err)
		originalBytes := make([]byte, len(originalSecret.Data.SecureBytes()))
		copy(originalBytes, originalSecret.Data.SecureBytes())
		originalSecret.Data.Destroy()

		updateReq := validUpsertKeyVersionRequest(tenant.ID, key1.ID)
		updateReq.ParentId = key0.ID
		updateReq.ParentVersion = 1
		updateReq.ProcessingState = string(model.KeyVersionReWrapping)

		// when
		_, err = setup.cli.UpsertKeyVersion(ctx, updateReq)

		// then
		require.NoError(t, err)

		result, err := setup.kvStore.GetKeyVersion(ctx, store.GetKeyVersionQuery{
			TenantID: tenant.ID,
			KeyID:    key1.ID,
			Version:  int(updateReq.GetVersion()),
			Revision: int(updateReq.GetRevision()),
		})
		require.NoError(t, err)
		assert.Equal(t, model.KeyVersionReWrapping, result.KeyVersion.ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, result.KeyVersion.LifeCycleState)

		// revert processing state to usable so ExportSecret can resolve the key version
		err = setup.kvStore.UpdateKeyVersionStates(ctx, store.UpdateKeyVersionStatesQuery{
			TenantID:            tenant.ID,
			KeyID:               key1.ID,
			Version:             int(updateReq.GetVersion()),
			Revision:            int(updateReq.GetRevision()),
			FromProcessingState: []model.KeyVersionProcessingState{model.KeyVersionReWrapping},
			ToProcessingState:   model.KeyVersionUsable,
			FromLifeCycleState:  []model.KeyLifeCycleState{model.KeyLifeCycleActive},
			ToLifeCycleState:    model.KeyLifeCycleActive,
		})
		require.NoError(t, err)

		updatedSecret, err := setup.manager.ExportSecret(ctx, keyprocessor.ExportSecretRequest{
			TenantID:   tenant.ID,
			KeyID:      key1.ID,
			KeyVersion: int(updateReq.GetVersion()),
		})
		require.NoError(t, err)
		updatedBytes := make([]byte, len(updatedSecret.Data.SecureBytes()))
		copy(updatedBytes, updatedSecret.Data.SecureBytes())
		updatedSecret.Data.Destroy()

		assert.Equal(t, originalBytes, updatedBytes)
	})
}
