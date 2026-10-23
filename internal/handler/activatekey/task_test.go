package activatekey_test

import (
	"database/sql"
	"encoding/json/v2"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/handler/activatekey"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestActivate_Handler(t *testing.T) {
	rootName := "test-root"
	rootDB := newRootDB(t)
	kStore := storesql.NewKeyStore(rootDB)
	kvStore := storesql.NewKeyVersionStore(rootDB)
	tenant := createTenant(t, rootDB)
	id := handler.KeyIdentifier{
		ID:       "",
		TenantID: tenant.ID,
	}
	_, err := json.Marshal(id)
	require.NoError(t, err)

	ctx := t.Context()

	validHierarchy := spec.KeyHierarchy{
		Name: "production-hierarchy",
		KeySpecs: []spec.KeySpec{
			{
				Kind:      "K0",
				Role:      spec.KeyRoleRoot,
				Algorithm: cryptor.KeyAlgorithmAES256,
			},
			{
				Kind:      "K1",
				Role:      spec.KeyRoleKek,
				Algorithm: cryptor.KeyAlgorithmAES256,
			},
			{
				Kind:      "K2",
				Role:      spec.KeyRoleTek,
				Algorithm: cryptor.KeyAlgorithmAES256,
			},
			{
				Kind:      "K3",
				Role:      spec.KeyRoleDek,
				Algorithm: cryptor.KeyAlgorithmAES256,
			},
		},
	}

	validRootCfg := config.RootConfig{
		Hierarchy: validHierarchy,
	}

	mgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
		KeyStore:        kStore,
		KeyVersionStore: kvStore,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			"K0": {
				SealerSpec:  newTestSealerSpec(t),
				CryptorSpec: newTestCryptorSpec(),
				VaultSpec:   newTestVaultSpec(),
			},
			"K1": {
				SealerSpec:  newTestSealerSpec(t),
				CryptorSpec: newTestCryptorSpec(),
				VaultSpec:   newTestVaultSpec(),
			},
		},
		Hierarchy: validHierarchy,
		Registry:  nil,
	})

	require.NoError(t, err)

	subj := activatekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		nil,
		rootName,
		mgr,
		validRootCfg,
	)

	t.Run("should fail if task data is invalid", func(t *testing.T) {
		// given

		// when
		resp := runTask(t, subj, []byte("invalid-json"))
		// then

		assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
		assert.Zero(t, resp.ReconcileAfterSec)
	})

	t.Run("should fail if key is not present", func(t *testing.T) {
		// given
		unknownKeyID := uuid.New().String()
		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       unknownKeyID,
			TenantID: tenant.ID,
		})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
		assert.Zero(t, resp.ReconcileAfterSec)
	})

	t.Run("should retry if the get key returns a internal error", func(t *testing.T) {
		// given
		invalidUUID := "non-uuid"
		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       invalidUUID,
			TenantID: tenant.ID,
		})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
		assert.Positive(t, resp.ReconcileAfterSec)
	})

	t.Run("should succeed if key is present and in not in active state", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleDeactivated,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key.ID,
			TenantID: tenant.ID,
		})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)
	})

	t.Run("should succeed if key is present status is not in pending status", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingFailed},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key.ID,
			TenantID: tenant.ID,
		})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)
	})

	t.Run("should ContinueAndWaitFor if tenant fetching fails", func(t *testing.T) {
		// given
		tmpDB := newRootDB(t)
		tmpStore := storesql.NewKeyStore(tmpDB)
		tmpTenant := createTenant(t, tmpDB)

		key := createKey(t, tmpStore, model.Key{
			TenantID:           tmpTenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key.ID,
			TenantID: tmpTenant.ID,
		})

		subj := activatekey.NewTaskHandler(
			storesql.NewTransactor(tmpDB),
			nil,
			rootName,
			mgr,
			validRootCfg,
		)

		renameTenantTable(t, tmpDB)

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
		assert.Positive(t, resp.ReconcileAfterSec)
	})

	t.Run("should return error if parent keyversion is not present", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleDeactivated
		})

		key1 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K1",
			ParentID:           new(key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key1.ID,
			TenantID: tenant.ID,
		})

		// when
		// make sure no keyversion is present for the key
		kvlist1, err := kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: key1.TenantID,
			KeyID:    key1.ID,
		})
		require.NoError(t, err)
		assert.Empty(t, kvlist1.KeyVersions)

		// resolve and upsert keyversion for the key
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)

		// fetch key k1
		fetchedKey1, err := kStore.GetKeyByID(ctx, key1.ID, key1.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingFailed, fetchedKey1.KeyProcessingState.Status)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKey1.LifeCycleState)
	})

	t.Run("should fail if the key kind is invalid", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0-wrong", // making wrong kind to fail the generation of the secret
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key.ID,
			TenantID: tenant.ID,
		})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
		// fetch key
		fetchedKey, err := kStore.GetKeyByID(ctx, key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingFailed, fetchedKey.KeyProcessingState.Status)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKey.LifeCycleState)
	})

	t.Run("should continue and wait if the geneation of secret fails", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})

		_ = createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})

		key1 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K1",
			ParentID:           new(key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key1.ID,
			TenantID: tenant.ID,
		})

		// here we dont have k1 in the bindings so it will fail to generate the secret and should return ContinueAndWaitFor
		invalidMgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore:        kStore,
			KeyVersionStore: kvStore,
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {
					SealerSpec:  newTestSealerSpec(t),
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
				},
			},
			Hierarchy: validHierarchy,
			Registry:  nil,
		})

		require.NoError(t, err)

		subj := activatekey.NewTaskHandler(
			storesql.NewTransactor(rootDB),
			nil,
			rootName,
			invalidMgr,
			validRootCfg,
		)

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
	})

	t.Run("should fail if registry conn is nil", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})

		kv0 := createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil,
			func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionUsable
				kv.LifeCycleState = model.KeyLifeCycleActive
			})

		key1 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K1",
			ParentID:           new(key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})

		_ = createKeyVersion(t, kvStore, tenant.ID, key1.ID, 100, &key0.ID, &kv0.Version,
			func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionUsable
				kv.LifeCycleState = model.KeyLifeCycleActive
			})

		key2 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K2",
			ParentID:           new(key1.ID),
			ManagedBy:          "agent-1",
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key2.ID,
			TenantID: tenant.ID,
		})

		subj := activatekey.NewTaskHandler(
			storesql.NewTransactor(rootDB),
			nil, // registry is nil
			rootName,
			mgr,
			validRootCfg,
		)

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)

		fetchedKey, err := kStore.GetKeyByID(ctx, key2.ID, key2.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingFailed, fetchedKey.KeyProcessingState.Status)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKey.LifeCycleState)
	})

	// t.Run("should fail if registry dont have the agent name", func(t *testing.T) {
	// 	// given
	// 	key0 := createKey(t, kStore, model.Key{
	// 		TenantID:           tenant.ID,
	// 		Kind:               "K0",
	// 		ParentID:           nil,
	// 		ManagedBy:          rootName,
	// 		LifeCycleState:     model.KeyLifeCycleActive,
	// 		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
	// 	})
	//
	// 	kv0 := createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil,
	// 		func(kv *model.KeyVersion) {
	// 			kv.ProcessingState = model.KeyVersionUsable
	// 			kv.LifeCycleState = model.KeyLifeCycleActive
	// 		})
	//
	// 	key1 := createKey(t, kStore, model.Key{
	// 		TenantID:           tenant.ID,
	// 		Kind:               "K1",
	// 		ParentID:           new(key0.ID),
	// 		ManagedBy:          rootName,
	// 		LifeCycleState:     model.KeyLifeCycleActive,
	// 		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
	// 	})
	//
	// 	_ = createKeyVersion(t, kvStore, tenant.ID, key1.ID, 100, &key0.ID, &kv0.Version,
	// 		func(kv *model.KeyVersion) {
	// 			kv.ProcessingState = model.KeyVersionUsable
	// 			kv.LifeCycleState = model.KeyLifeCycleActive
	// 		})
	//
	// 	key2 := createKey(t, kStore, model.Key{
	// 		TenantID:           tenant.ID,
	// 		Kind:               "K2",
	// 		ParentID:           new(key1.ID),
	// 		ManagedBy:          "agent-1",
	// 		LifeCycleState:     model.KeyLifeCycleActive,
	// 		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
	// 	})
	//
	// 	taskdata := jsonMarshal(t, handler.KeyIdentifier{
	// 		ID:       key2.ID,
	// 		TenantID: tenant.ID,
	// 	})
	//
	// 	subj := activatekey.NewTaskHandler(
	// 		storesql.NewTransactor(rootDB),
	// 		nil, // registry is nil
	// 		rootName,
	// 		mgr,
	// 		validRootCfg,
	// 	)
	//
	// 	// when
	// 	resp := runTask(t, subj, taskdata)
	//
	// 	// then
	// 	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	//
	// 	fetchedKey, err := kStore.GetKeyByID(ctx, key2.ID, key2.TenantID)
	// 	require.NoError(t, err)
	// 	assert.Equal(t, model.KeyProcessingFailed, fetchedKey.KeyProcessingState.Status)
	// 	assert.Equal(t, model.KeyLifeCycleActive, fetchedKey.LifeCycleState)
	// })

	t.Run("should be successfully create key version for root key", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key0.ID,
			TenantID: tenant.ID,
		})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)

		fetchedKey, err := kStore.GetKeyByID(ctx, key0.ID, key0.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingCompleted, fetchedKey.KeyProcessingState.Status)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKey.LifeCycleState)

		fetchedKeyVersion, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: key0.TenantID,
			KeyID:    key0.ID,
		})
		require.NoError(t, err)
		require.Len(t, fetchedKeyVersion.KeyVersions, 1)
		assert.Equal(t, model.KeyVersionUsable, fetchedKeyVersion.KeyVersions[0].ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKeyVersion.KeyVersions[0].LifeCycleState)
	})

	t.Run("should be successfully create key version for non root key managed by root", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})

		kv0 := createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil,
			func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionUsable
				kv.LifeCycleState = model.KeyLifeCycleActive
			})

		key1 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K1",
			ParentID:           new(key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key1.ID,
			TenantID: tenant.ID,
		})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)

		fetchedKey, err := kStore.GetKeyByID(ctx, key0.ID, key0.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingCompleted, fetchedKey.KeyProcessingState.Status)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKey.LifeCycleState)

		fetchedKeyVersion, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: key1.TenantID,
			KeyID:    key1.ID,
		})
		require.NoError(t, err)
		require.Len(t, fetchedKeyVersion.KeyVersions, 1)
		assert.Equal(t, model.KeyVersionUsable, fetchedKeyVersion.KeyVersions[0].ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKeyVersion.KeyVersions[0].LifeCycleState)
		assert.Equal(t, kv0.Version, *fetchedKeyVersion.KeyVersions[0].ParentKeyVersion)
	})

	t.Run("should be successfully update key version for non root key managed by root", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})

		kv0 := createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil,
			func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionUsable
				kv.LifeCycleState = model.KeyLifeCycleActive
			})

		key1 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K1",
			ParentID:           new(key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		kv1 := createKeyVersion(t, kvStore, tenant.ID, key1.ID, 100, &key0.ID, &kv0.Version,
			func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionUsable
				kv.LifeCycleState = model.KeyLifeCycleSuspended
			})

		taskdata := jsonMarshal(t, handler.KeyIdentifier{
			ID:       key1.ID,
			TenantID: tenant.ID,
		})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)

		fetchedKey, err := kStore.GetKeyByID(ctx, key0.ID, key0.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingCompleted, fetchedKey.KeyProcessingState.Status)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKey.LifeCycleState)

		fetchedKeyVersion, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: key1.TenantID,
			KeyID:    key1.ID,
		})
		require.NoError(t, err)
		require.Len(t, fetchedKeyVersion.KeyVersions, 1)
		assert.Equal(t, kv1.KeyID, fetchedKeyVersion.KeyVersions[0].KeyID)
		assert.Equal(t, model.KeyVersionUsable, fetchedKeyVersion.KeyVersions[0].ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, fetchedKeyVersion.KeyVersions[0].LifeCycleState)
		assert.Equal(t, kv1.Version, fetchedKeyVersion.KeyVersions[0].Version)
		assert.Equal(t, kv0.Version, *fetchedKeyVersion.KeyVersions[0].ParentKeyVersion)
	})
}

func TestFetchExistingKeyVersion(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)
	stores := store.Stores{
		Keys:        kStore,
		KeyVersions: kvStore,
	}

	t.Run("should fetch and update already exisiting keyversion for the key", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		kv := createKeyVersion(t, kvStore, tenant.ID, key.ID, 1, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionReWrapping
			kv.LifeCycleState = model.KeyLifeCycleSuspended
		})

		// when
		actual, err := activatekey.FetchAndUpsertExistingKeyVersion(t.Context(), stores, key)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, actual)
		assert.Equal(t, kv.KeyID, actual.KeyID)
		assert.Equal(t, kv.Version, actual.Version)
		assert.Equal(t, kv.TenantID, actual.TenantID)
		assert.Equal(t, kv.KeyID, actual.KeyID)
		assert.Equal(t, kv.ParentKeyID, actual.ParentKeyID)
		assert.Equal(t, kv.ParentKeyVersion, actual.ParentKeyVersion)
		assert.Equal(t, model.KeyVersionUsable, actual.ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, actual.LifeCycleState)
	})

	t.Run("should return nil if no keyversion is present for the key", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		actual, err := activatekey.FetchAndUpsertExistingKeyVersion(t.Context(), stores, key)

		// then
		assert.ErrorIs(t, err, activatekey.ErrKeyVersionNotFound)
		assert.Nil(t, actual)
	})
}

func TestCreateKeyVersionFromParent(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)
	stores := store.Stores{
		Keys:        kStore,
		KeyVersions: kvStore,
	}
	t.Run("should create a new keyversion for the key if not present", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		// make sure no keyversion is present for the key
		kvlist, err := kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: key.TenantID,
			KeyID:    key.ID,
		})
		require.NoError(t, err)
		assert.Empty(t, kvlist.KeyVersions)

		// resolve and upsert keyversion for the key
		actual, err := activatekey.CreateAndUpsertKeyVersionFromParent(t.Context(), stores, key)

		// then
		assert.NoError(t, err)

		// make sure a new keyversion is created for the key
		kvlist, err = kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: key.TenantID,
			KeyID:    key.ID,
		})
		require.NoError(t, err)
		assert.Len(t, kvlist.KeyVersions, 1)

		assert.NotNil(t, actual)
		assert.Equal(t, kvlist.KeyVersions[0].KeyID, actual.KeyID)
		assert.Equal(t, kvlist.KeyVersions[0].Version, actual.Version)
		assert.Equal(t, kvlist.KeyVersions[0].TenantID, actual.TenantID)
		assert.Equal(t, kvlist.KeyVersions[0].KeyID, actual.KeyID)
		assert.Equal(t, kvlist.KeyVersions[0].ParentKeyID, actual.ParentKeyID)
		assert.Equal(t, kvlist.KeyVersions[0].ParentKeyVersion, actual.ParentKeyVersion)
		assert.Equal(t, kvlist.KeyVersions[0].ProcessingState, actual.ProcessingState)
		assert.Equal(t, kvlist.KeyVersions[0].LifeCycleState, actual.LifeCycleState)
		assert.Equal(t, model.KeyVersionUsable, actual.ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, actual.LifeCycleState)
	})

	t.Run("should create a new keyversion for the key based on parent keyversion if parent is present", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		kv0 := createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})

		key1 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K1",
			ParentID:           new(key0.ID),
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		// make sure no keyversion is present for the key
		kvlist1, err := kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: key1.TenantID,
			KeyID:    key1.ID,
		})
		require.NoError(t, err)
		assert.Empty(t, kvlist1.KeyVersions)

		// resolve and upsert keyversion for the key
		actual, err := activatekey.CreateAndUpsertKeyVersionFromParent(t.Context(), stores, key1)

		// then
		assert.NoError(t, err)

		// make sure a new keyversion is created for the key
		kvlist1, err = kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: key1.TenantID,
			KeyID:    key1.ID,
		})
		require.NoError(t, err)
		assert.Len(t, kvlist1.KeyVersions, 1)

		assert.NotNil(t, actual)
		assert.Equal(t, kvlist1.KeyVersions[0].KeyID, actual.KeyID)
		assert.Equal(t, kvlist1.KeyVersions[0].Version, actual.Version)
		assert.Equal(t, kvlist1.KeyVersions[0].TenantID, actual.TenantID)
		assert.Equal(t, kvlist1.KeyVersions[0].KeyID, actual.KeyID)
		assert.Equal(t, kvlist1.KeyVersions[0].ParentKeyID, actual.ParentKeyID)
		assert.Equal(t, kvlist1.KeyVersions[0].ParentKeyVersion, actual.ParentKeyVersion)
		assert.Equal(t, kvlist1.KeyVersions[0].ProcessingState, actual.ProcessingState)
		assert.Equal(t, kvlist1.KeyVersions[0].LifeCycleState, actual.LifeCycleState)
		assert.Equal(t, model.KeyVersionUsable, actual.ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, actual.LifeCycleState)
		assert.Equal(t, kv0.KeyID, *actual.ParentKeyID)
		assert.Equal(t, kv0.Version, *actual.ParentKeyVersion)
	})

	t.Run("should return error if parent keyversion is not present", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K0",
			ParentID:           nil,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleDeactivated
		})

		key1 := createKey(t, kStore, model.Key{
			TenantID:           tenant.ID,
			Kind:               "K1",
			ParentID:           new(key0.ID),
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		// make sure no keyversion is present for the key
		kvlist1, err := kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: key1.TenantID,
			KeyID:    key1.ID,
		})
		require.NoError(t, err)
		assert.Empty(t, kvlist1.KeyVersions)

		// resolve and upsert keyversion for the key
		actual, err := activatekey.CreateAndUpsertKeyVersionFromParent(t.Context(), stores, key1)

		// then
		assert.ErrorIs(t, err, activatekey.ErrTaskFailed)
		assert.Nil(t, actual)
	})
}

func jsonMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// renameTenantTable renames the tenants table to make GetTenant fail with a DB error,
// and returns a cleanup function that restores it.
func renameTenantTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), "ALTER TABLE tenants RENAME TO tenants_hidden")
	require.NoError(t, err)
}

func createKeyVersion(
	t *testing.T,
	db store.KeyVersion,
	tenantID, keyID string,
	version int,
	parentID *string,
	parentKeyVersion *int,
	opts ...func(*model.KeyVersion),
) model.KeyVersion {
	t.Helper()
	kv := model.NewKeyVersion(tenantID, keyID, version, parentID, parentKeyVersion)
	for _, opt := range opts {
		opt(&kv)
	}
	res, err := db.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
	require.NoError(t, err)
	return res.KeyVersion
}
