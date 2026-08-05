package keys_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestActivateKey(t *testing.T) {
	// given
	ctx := t.Context()
	rootTopology := rootTestTopology()

	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(ctx, db))

	t.Run("should activate root key version", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), &noopJobPreparer{}, &rootTopology)
		cli := setup.cli
		keyStore := setup.keyStore
		keyVersionStore := setup.keyVersionStore
		tenant := createTenant(t, setup.tenantStore)

		// announcing root key
		announceRes, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)

		rootID := announceRes.GetKey().GetId()

		// when
		activateRes, err := cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       rootID,
		})
		require.NoError(t, err)
		assert.NotNil(t, activateRes)

		// then
		// Verify that the key is activated
		key, err := keyStore.GetKeyByID(ctx, rootID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, key.KeyProcessingState.Status)

		// Verify that the keyversion is also created and activated
		keyVersion, err := keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenant.ID,
			KeyID:           rootID,
			Version:         1,
			LifeCycleState:  model.KeyLifeCycleActive,
			ProcessingState: model.KeyVersionUsable,
			Limit:           100,
		})

		require.NoError(t, err)
		assert.Len(t, keyVersion.KeyVersions, 1)
	})

	t.Run("should not activate root key version twice", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), &noopJobPreparer{}, &rootTopology)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		// announcing root key
		announceRes, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)

		rootID := announceRes.GetKey().GetId()

		// when
		activateRes, err := cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       rootID,
		})
		require.NoError(t, err)
		assert.NotNil(t, activateRes)

		activateRes, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       rootID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, activateRes)
	})

	t.Run("should activate a intermediate key", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), &noopJobPreparer{}, &rootTopology)
		cli := setup.cli
		keyStore := setup.keyStore
		keyVersionStore := setup.keyVersionStore
		tenant := createTenant(t, setup.tenantStore)

		// announcing root key
		announceRes, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		rootKeyID := announceRes.GetKey().GetId()

		// activating root key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       rootKeyID,
		})
		require.NoError(t, err)

		// announcing k1 key
		announceRes, err = cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "k1-key-" + uuid.NewString(),
			ParentId:   rootKeyID,
			TargetName: testRootName,
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		keyID := announceRes.GetKey().GetId()

		// when
		// activating k1 key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       keyID,
		})
		require.NoError(t, err)

		// then
		// Verify that the key is activated
		key, err := keyStore.GetKeyByID(ctx, keyID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, key.KeyProcessingState.Status)

		// Verify that the keyversion is also created and activated
		keyVersion, err := keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenant.ID,
			KeyID:           keyID,
			Version:         1,
			LifeCycleState:  model.KeyLifeCycleActive,
			ProcessingState: model.KeyVersionUsable,
			Limit:           100,
		})

		require.NoError(t, err)
		assert.Len(t, keyVersion.KeyVersions, 1)

		// check if the secret is store in the vault
		kv := keyVersion.KeyVersions[0]
		vaultK1, err := vaultprovider.GetVault(ctx, *setup.vaultK1)
		require.NoError(t, err)
		vaultResp, err := vaultK1.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:    kv.TenantID,
			KeyID:       keyID,
			KeyVersion:  kv.Version,
			KeyRevision: kv.Revision,
		})

		require.NoError(t, err)
		assert.NotEmpty(t, vaultResp.KeyMaterial)
	})

	t.Run("should not activate a intermediate key twice", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), &noopJobPreparer{}, &rootTopology)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		// announcing root key
		announceRes, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		rootKeyID := announceRes.GetKey().GetId()

		// activating root key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       rootKeyID,
		})
		require.NoError(t, err)

		// announcing k1 key
		announceRes, err = cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "k1-key-" + uuid.NewString(),
			ParentId:   rootKeyID,
			TargetName: testRootName,
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		keyID := announceRes.GetKey().GetId()

		// when
		// activating k1 key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       keyID,
		})
		require.NoError(t, err)

		activateRes, err := cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       keyID,
		})
		assert.Error(t, err)
		assert.Nil(t, activateRes)
	})

	t.Run("should activate all keys in a chain", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), &noopJobPreparer{}, &rootTopology)
		cli := setup.cli
		keyVersionStore := setup.keyVersionStore
		tenant := createTenant(t, setup.tenantStore)

		// given
		// announcing root key
		var k0ID, k1ID, k2ID, k3ID string
		announceRes, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		k0ID = announceRes.GetKey().GetId()

		// when
		// activating root key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       k0ID,
		})
		// then
		require.NoError(t, err)

		// given
		// announcing k1 key
		announceRes, err = cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "k1-key-" + uuid.NewString(),
			ParentId:   k0ID,
			TargetName: testRootName,
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		k1ID = announceRes.GetKey().GetId()

		// when
		// activating root key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       k1ID,
		})
		// then
		require.NoError(t, err)

		// given
		// announcing k2 key
		announceRes, err = cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K2",
			Name:       "k2-key-" + uuid.NewString(),
			ParentId:   k1ID,
			TargetName: testRootName,
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		k2ID = announceRes.GetKey().GetId()

		// when
		// activating root key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       k2ID,
		})
		// then
		require.NoError(t, err)

		// given
		// announcing k3 key
		announceRes, err = cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K3",
			Name:       "k3-key-" + uuid.NewString(),
			ParentId:   k2ID,
			TargetName: testRootName,
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		k3ID = announceRes.GetKey().GetId()

		// when
		// activating root key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       k3ID,
		})
		// then
		require.NoError(t, err)

		// Verify that the keyversion is also created and activated
		keyVersion, err := keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenant.ID,
			KeyID:           k3ID,
			Version:         1,
			LifeCycleState:  model.KeyLifeCycleActive,
			ProcessingState: model.KeyVersionUsable,
			Limit:           100,
		})

		require.NoError(t, err)
		assert.Len(t, keyVersion.KeyVersions, 1)

		// check if the secret is store in the vault
		kv := keyVersion.KeyVersions[0]
		vaultK3, err := vaultprovider.GetVault(ctx, *setup.vaultK3)
		require.NoError(t, err)
		vaultResp, err := vaultK3.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:    kv.TenantID,
			KeyID:       k3ID,
			KeyVersion:  kv.Version,
			KeyRevision: kv.Revision,
		})

		require.NoError(t, err)
		assert.NotEmpty(t, vaultResp.KeyMaterial)
	})

	t.Run("should return error if there is no parent keyversion", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), &noopJobPreparer{}, &rootTopology)
		cli := setup.cli
		keyVersionStore := setup.keyVersionStore
		tenant := createTenant(t, setup.tenantStore)

		// announcing root key
		announceRes, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		rootKeyID := announceRes.GetKey().GetId()

		// activating root key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       rootKeyID,
		})
		require.NoError(t, err)

		// making the keyversion to pending to simulate that the parent keyversion is not usable
		err = keyVersionStore.UpdateKeyVersionStates(ctx, store.UpdateKeyVersionStatesQuery{
			TenantID:            tenant.ID,
			KeyID:               rootKeyID,
			Version:             1,
			Revision:            1,
			FromProcessingState: []model.KeyVersionProcessingState{model.KeyVersionUsable},
			ToProcessingState:   model.KeyVersionActivating,
			FromLifeCycleState:  []model.KeyLifeCycleState{model.KeyLifeCycleActive},
			ToLifeCycleState:    model.KeyLifeCycleCompromised,
		})
		require.NoError(t, err)

		// announcing k1 key
		announceRes, err = cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "k1-key-" + uuid.NewString(),
			ParentId:   rootKeyID,
			TargetName: testRootName,
			Labels:     map[string]string{"env": "prod"},
		})
		require.NoError(t, err)
		keyID := announceRes.GetKey().GetId()

		// when
		// activating k1 key
		_, err = cli.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       keyID,
		})
		require.Error(t, err)
	})
}
