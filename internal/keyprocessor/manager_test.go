package keyprocessor_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestManagerSeal(t *testing.T) {
	t.Run("should return error if key version is empty", func(t *testing.T) {
		// given
		c := keyprocessor.NewTestManager(nil, nil, nil)

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:  uuid.NewString(),
			KeyID:     uuid.NewString(),
			Plaintext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrKeyVersionRequired)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should return error if key version resolution fails", func(t *testing.T) {
		// given
		kvStoreErr := errors.New("database unavailable")
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			assert.Equal(t, keyID, q.KeyID)
			assert.Equal(t, tenantID, q.TenantID)
			return store.ListKeyVersionsResult{}, kvStoreErr
		}
		c := keyprocessor.NewTestManager(nil, kvs, nil)

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, kvStoreErr)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should return error if no usable key version found", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{KeyVersions: []model.KeyVersion{}}, nil
		}
		c := keyprocessor.NewTestManager(nil, kvs, nil)

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrNoUsableKeyVersion)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should return error if store lookup fails", func(t *testing.T) {
		// given
		storeErr := errors.New("database unavailable")
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: tenantID, KeyID: keyID, Version: 1, ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, id, tid string) (*model.Key, error) {
			assert.Equal(t, keyID, id)
			assert.Equal(t, tenantID, tid)
			return nil, storeErr
		}
		c := keyprocessor.NewTestManager(ks, kvs, nil)

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, storeErr)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should return error if key is not active", func(t *testing.T) {
		// given
		key := &model.Key{
			ID:             uuid.NewString(),
			TenantID:       uuid.NewString(),
			Kind:           "K1",
			LifeCycleState: model.KeyLifeCycleDeactivated,
		}

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: key.TenantID, KeyID: key.ID, Version: 1, ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, _, _ string) (*model.Key, error) {
			return key, nil
		}
		c := keyprocessor.NewTestManager(ks, kvs, nil)

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrKeyNotActivated)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should return error if processor not found for key kind", func(t *testing.T) {
		// given
		key := &model.Key{
			ID:             uuid.NewString(),
			TenantID:       uuid.NewString(),
			Kind:           "UNKNOWN_KIND",
			LifeCycleState: model.KeyLifeCycleActive,
		}

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: key.TenantID, KeyID: key.ID, Version: 1, ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, _, _ string) (*model.Key, error) {
			return key, nil
		}
		c := keyprocessor.NewTestManager(ks, kvs, map[model.KeyKind]keyprocessor.Processor{})

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrProcessorNotFound)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should succeed", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		rootKey := model.NewKey(tenantID, "root-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		activateKey(t, db, rootKey)
		rootMgr := keyprocessor.NewTestRootManager(keyStore, newTestSealer(t))

		key := model.NewKey(tenantID, "enc-key-"+uuid.NewString(), "K1", &rootKey.ID, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), key))
		activateKey(t, db, key)

		kv := model.NewKeyVersion(tenantID, key.ID, 1, &rootKey.ID, nil)
		_, err := kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
		require.NoError(t, err)

		proc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, rootMgr, newTestVault(t))
		_, err = proc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
		assert.NoError(t, err)

		c := keyprocessor.NewTestManager(keyStore, kvStore, map[model.KeyKind]keyprocessor.Processor{key.Kind: *proc})

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   tenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("secret payload")),
			AAD:        []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp.Ciphertext)
		assert.NotEmpty(t, resp.Ciphertext.SecureBytes())
	})
}

func TestManagerUnseal(t *testing.T) {
	t.Run("should return error if key version is empty", func(t *testing.T) {
		// given
		c := keyprocessor.NewTestManager(nil, nil, nil)

		// when
		resp, err := c.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   uuid.NewString(),
			KeyID:      uuid.NewString(),
			Ciphertext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrKeyVersionRequired)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})

	t.Run("should return error if key version resolution fails", func(t *testing.T) {
		// given
		kvStoreErr := errors.New("database unavailable")
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			assert.Equal(t, keyID, q.KeyID)
			assert.Equal(t, tenantID, q.TenantID)
			return store.ListKeyVersionsResult{}, kvStoreErr
		}
		c := keyprocessor.NewTestManager(nil, kvs, nil)

		// when
		resp, err := c.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: 1,
			Ciphertext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, kvStoreErr)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})

	t.Run("should return error if store lookup fails", func(t *testing.T) {
		// given
		storeErr := errors.New("database unavailable")
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: tenantID, KeyID: keyID, Version: 1, ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, _, _ string) (*model.Key, error) {
			return nil, storeErr
		}
		c := keyprocessor.NewTestManager(ks, kvs, nil)

		// when
		resp, err := c.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: 1,
			Ciphertext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, storeErr)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})

	t.Run("should return error if processor not found for key kind", func(t *testing.T) {
		// given
		key := &model.Key{
			ID:             uuid.NewString(),
			TenantID:       uuid.NewString(),
			Kind:           "UNKNOWN_KIND",
			LifeCycleState: model.KeyLifeCycleActive,
		}

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: key.TenantID, KeyID: key.ID, Version: 1, ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, _, _ string) (*model.Key, error) {
			return key, nil
		}
		c := keyprocessor.NewTestManager(ks, kvs, map[model.KeyKind]keyprocessor.Processor{})

		// when
		resp, err := c.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Ciphertext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrProcessorNotFound)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})

	t.Run("should succeed with round trip", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		rootKey := model.NewKey(tenantID, "root-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		activateKey(t, db, rootKey)
		rootMgr := keyprocessor.NewTestRootManager(keyStore, newTestSealer(t))

		key := model.NewKey(tenantID, "dec-key-"+uuid.NewString(), "K1", &rootKey.ID, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), key))
		activateKey(t, db, key)

		kv := model.NewKeyVersion(tenantID, key.ID, 1, &rootKey.ID, nil)
		_, err := kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
		require.NoError(t, err)

		proc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, rootMgr, newTestVault(t))
		_, err = proc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
		assert.NoError(t, err)

		c := keyprocessor.NewTestManager(keyStore, kvStore, map[model.KeyKind]keyprocessor.Processor{key.Kind: *proc})

		sealResp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   tenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("round trip data")),
			AAD:        []byte("aad"),
		})
		assert.NoError(t, err)

		// when
		unsealResp, err := c.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   tenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Ciphertext: sealResp.Ciphertext,
			AAD:        []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("round trip data"), []byte(unsealResp.Plaintext.SecureBytes()))
	})
}

func TestRootManager(t *testing.T) {
	t.Run("should return error if store lookup fails", func(t *testing.T) {
		// given
		storeErr := errors.New("store unavailable")
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, _, _ string) (*model.Key, error) {
			return nil, storeErr
		}
		c := keyprocessor.NewTestRootManager(ks, newTestSealer(t))

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:  uuid.NewString(),
			KeyID:     uuid.NewString(),
			Plaintext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, storeErr)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should return error if key is not active", func(t *testing.T) {
		// given
		key := &model.Key{
			ID:             uuid.NewString(),
			TenantID:       uuid.NewString(),
			LifeCycleState: model.KeyLifeCycleDeactivated,
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, _, _ string) (*model.Key, error) {
			return key, nil
		}
		c := keyprocessor.NewTestRootManager(ks, newTestSealer(t))

		// when
		resp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:  key.TenantID,
			KeyID:     key.ID,
			Plaintext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrKeyNotActivated)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should seal and unseal successfully", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		key := model.NewKey(tenantID, "root-key-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), key))
		activateKey(t, db, key)

		c := keyprocessor.NewTestRootManager(keyStore, newTestSealer(t))

		// when
		sealResp, err := c.Seal(t.Context(), cryptor.SealRequest{
			TenantID:  tenantID,
			KeyID:     key.ID,
			Plaintext: newTestData(t, []byte("root secret")),
			AAD:       []byte("aad"),
		})
		assert.NoError(t, err)

		unsealResp, err := c.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   tenantID,
			KeyID:      key.ID,
			Ciphertext: sealResp.Ciphertext,
			AAD:        []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("root secret"), []byte(unsealResp.Plaintext.SecureBytes()))
	})
}

func TestManagerHierarchy(t *testing.T) {
	t.Run("should succeed for three-level chain round trip", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		// root level
		rootKey := model.NewKey(tenantID, "root-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		activateKey(t, db, rootKey)
		rootMgr := keyprocessor.NewTestRootManager(keyStore, newTestSealer(t))

		// mid level
		midKey := model.NewKey(tenantID, "mid-"+uuid.NewString(), "K1", &rootKey.ID, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), midKey))
		activateKey(t, db, midKey)
		midKV := model.NewKeyVersion(tenantID, midKey.ID, 1, &rootKey.ID, nil)
		_, err := kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: midKV})
		require.NoError(t, err)

		midProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newTestSealer(t), rootMgr, newTestVault(t))
		_, err = midProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: midKV})
		assert.NoError(t, err)
		midMgr := keyprocessor.NewTestManager(keyStore, kvStore, map[model.KeyKind]keyprocessor.Processor{"K1": *midProc})

		// leaf level
		leafKey := model.NewKey(tenantID, "leaf-"+uuid.NewString(), "K2", &midKey.ID, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), leafKey))
		activateKey(t, db, leafKey)
		leafKV := model.NewKeyVersion(tenantID, leafKey.ID, 1, &midKey.ID, &midKV.Version)
		_, err = kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: leafKV})
		require.NoError(t, err)

		leafProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, midMgr, newTestVault(t))
		_, err = leafProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: leafKV})
		assert.NoError(t, err)
		leafMgr := keyprocessor.NewTestManager(keyStore, kvStore, map[model.KeyKind]keyprocessor.Processor{"K2": *leafProc})

		// when
		sealResp, err := leafMgr.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   tenantID,
			KeyID:      leafKey.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("top secret")),
		})
		assert.NoError(t, err)

		unsealResp, err := leafMgr.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   tenantID,
			KeyID:      leafKey.ID,
			KeyVersion: 1,
			Ciphertext: sealResp.Ciphertext,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("top secret"), []byte(unsealResp.Plaintext.SecureBytes()))
	})
}

func TestNewManager(t *testing.T) {
	t.Run("should return error when root binding has nil sealer spec", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: nil},
				"K1": {},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.Nil(t, mgr)
		assert.ErrorIs(t, err, keyprocessor.ErrRootMissingSealerSpec)
	})

	t.Run("should return error when root sealer provider fails", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: &sealerprovider.Spec{Name: "bad", Config: nil}},
				"K1": {},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.Nil(t, mgr)
		assert.ErrorIs(t, err, cryptor.ErrUnknownType)
	})

	t.Run("should return error when non-root cryptor provider fails", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: newTestSealerSpec(t)},
				"K1": {CryptorSpec: &cryptorprovider.Spec{Name: "bad", Config: nil}},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.Nil(t, mgr)
		assert.ErrorContains(t, err, "building processor for key kind K1")
		assert.ErrorIs(t, err, cryptor.ErrUnknownType)
	})

	t.Run("should return error when non-root vault provider fails", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: newTestSealerSpec(t)},
				"K1": {
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   &vaultprovider.Spec{Name: "bad", Type: "unknown-type"},
				},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.Nil(t, mgr)
		assert.ErrorContains(t, err, "building processor for key kind K1")
	})

	t.Run("should return error when non-root transport sealer provider fails", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: newTestSealerSpec(t)},
				"K1": {
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
					SealerSpec:  &sealerprovider.Spec{Name: "bad", Config: nil},
				},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.Nil(t, mgr)
		assert.ErrorContains(t, err, "building processor for key kind K1")
		assert.ErrorIs(t, err, cryptor.ErrUnknownType)
	})

	t.Run("should return error when key store is nil", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        nil,
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: newTestSealerSpec(t)},
				"K1": {CryptorSpec: newTestCryptorSpec(), VaultSpec: newTestVaultSpec()},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.Nil(t, mgr)
		assert.ErrorIs(t, err, keyprocessor.ErrKeyStoreMissing)
	})

	t.Run("should return error when key version store is nil", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: nil,
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: newTestSealerSpec(t)},
				"K1": {CryptorSpec: newTestCryptorSpec(), VaultSpec: newTestVaultSpec()},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.Nil(t, mgr)
		assert.ErrorIs(t, err, keyprocessor.ErrKeyVersionStoreMissing)
	})

	t.Run("should construct manager for two-level hierarchy", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: newTestSealerSpec(t)},
				"K1": {
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
				},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, mgr)
	})

	t.Run("should construct manager for three-level hierarchy", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleKek},
					{Kind: "K2", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: newTestSealerSpec(t)},
				"K1": {
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
				},
				"K2": {
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
				},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, mgr)
	})

	t.Run("should construct manager with transport sealer", func(t *testing.T) {
		// given
		cfg := keyprocessor.ManagerConfig{
			KeyStore:        &keyStoreWrapper{},
			KeyVersionStore: &keyVersionStoreWrapper{},
			Hierarchy: spec.KeyHierarchy{
				Name: "test",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot},
					{Kind: "K1", Role: spec.KeyRoleDek},
				},
			},
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K0": {SealerSpec: newTestSealerSpec(t)},
				"K1": {
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
					SealerSpec:  newTestSealerSpec(t),
				},
			},
		}

		// when
		mgr, err := keyprocessor.NewManager(t.Context(), cfg)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, mgr)
	})

	t.Run("should construct manager for two nodes", func(t *testing.T) {
		t.Run("with root bindings", func(t *testing.T) {
			// given
			cfg := keyprocessor.ManagerConfig{
				KeyStore:        &keyStoreWrapper{},
				KeyVersionStore: &keyVersionStoreWrapper{},
				Hierarchy: spec.KeyHierarchy{
					Name: "test",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot},
						{Kind: "K1", Role: spec.KeyRoleDek},
						{Kind: "K2", Role: spec.KeyRoleTek},
						{Kind: "K3", Role: spec.KeyRoleDek},
					},
				},
				Bindings: map[model.KeyKind]spec.KeyBinding{
					"K0": {
						SealerSpec: newTestSealerSpec(t),
					},
					"K1": {
						CryptorSpec: newTestCryptorSpec(),
						VaultSpec:   newTestVaultSpec(),
					},
				},
			}

			// when
			mgr, err := keyprocessor.NewManager(t.Context(), cfg)

			// then
			assert.NoError(t, err)
			assert.NotNil(t, mgr)
		})

		t.Run("with agent bindings", func(t *testing.T) {
			// given
			cfg := keyprocessor.ManagerConfig{
				KeyStore:        &keyStoreWrapper{},
				KeyVersionStore: &keyVersionStoreWrapper{},
				Hierarchy: spec.KeyHierarchy{
					Name: "test",
					KeySpecs: []spec.KeySpec{
						{Kind: "K0", Role: spec.KeyRoleRoot},
						{Kind: "K1", Role: spec.KeyRoleDek},
						{Kind: "K2", Role: spec.KeyRoleTek},
						{Kind: "K3", Role: spec.KeyRoleDek},
					},
				},
				Bindings: map[model.KeyKind]spec.KeyBinding{
					"K2": {
						CryptorSpec: newTestCryptorSpec(),
						VaultSpec:   newTestVaultSpec(),
						SealerSpec:  newTestSealerSpec(t),
					},
					"K3": {
						CryptorSpec: newTestCryptorSpec(),
						VaultSpec:   newTestVaultSpec(),
					},
				},
			}

			// when
			mgr, err := keyprocessor.NewManager(t.Context(), cfg)

			// then
			assert.NoError(t, err)
			assert.NotNil(t, mgr)
		})
	})
}

type keyStoreWrapper struct {
	store.Key

	getKeyByIDFn func(context.Context, string, string) (*model.Key, error)
}

func (w *keyStoreWrapper) GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error) {
	if w.getKeyByIDFn != nil {
		return w.getKeyByIDFn(ctx, id, tenantID)
	}
	return w.Key.GetKeyByID(ctx, id, tenantID)
}

type keyVersionStoreWrapper struct {
	store.KeyVersion

	listKeyVersionsFn func(context.Context, store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error)
}

func (w *keyVersionStoreWrapper) ListKeyVersions(ctx context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
	if w.listKeyVersionsFn != nil {
		return w.listKeyVersionsFn(ctx, q)
	}
	return w.KeyVersion.ListKeyVersions(ctx, q)
}

func newTestSealerSpec(t *testing.T) *sealerprovider.Spec {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	envName := "TEST_SEALER_KEY_" + uuid.NewString()[:8]
	t.Setenv(envName, base64.StdEncoding.EncodeToString(key))

	return &sealerprovider.Spec{
		Name: "test-sealer",
		Type: staticsecret.TypeStaticSecret,
		Config: &staticsecret.Config{
			Secret: secretprovider.Spec{
				Type:   envvar.Type,
				Config: &envvar.Config{Name: envName},
			},
		},
	}
}

func newTestCryptorSpec() *cryptorprovider.Spec {
	return &cryptorprovider.Spec{
		Name:   "test-cryptor",
		Type:   aes256gcm.TypeAES256GCM,
		Config: &aes256gcm.Config{},
	}
}

func newTestVaultSpec() *vaultprovider.Spec {
	return &vaultprovider.Spec{
		Name: "test-vault",
		Type: sqlitevault.TypeUnsafeMemory,
	}
}

func TestManagerExportSecret(t *testing.T) {
	t.Run("should return error if key version resolution fails", func(t *testing.T) {
		// given
		kvStoreErr := errors.New("database unavailable")
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			assert.Equal(t, keyID, q.KeyID)
			assert.Equal(t, tenantID, q.TenantID)
			return store.ListKeyVersionsResult{}, kvStoreErr
		}
		c := keyprocessor.NewTestManager(nil, kvs, nil)

		// when
		sec, err := c.ExportSecret(t.Context(), keyprocessor.ExportSecretRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: 1,
		})

		// then
		assert.ErrorIs(t, err, kvStoreErr)
		assert.Equal(t, cryptor.Secret{}, sec)
	})

	t.Run("should return error if no usable key version found", func(t *testing.T) {
		tests := []struct {
			name       string
			keyVersion int
		}{
			{name: "explicit version", keyVersion: 1},
			{name: "empty version", keyVersion: 0},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				// given
				kvs := &keyVersionStoreWrapper{}
				kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
					return store.ListKeyVersionsResult{KeyVersions: []model.KeyVersion{}}, nil
				}
				c := keyprocessor.NewTestManager(nil, kvs, nil)

				// when
				sec, err := c.ExportSecret(t.Context(), keyprocessor.ExportSecretRequest{
					TenantID:   uuid.NewString(),
					KeyID:      uuid.NewString(),
					KeyVersion: tc.keyVersion,
				})

				// then
				assert.ErrorIs(t, err, keyprocessor.ErrNoUsableKeyVersion)
				assert.Equal(t, cryptor.Secret{}, sec)
			})
		}
	})

	t.Run("should resolve key version with expected query", func(t *testing.T) {
		tests := []struct {
			name                   string
			keyVersion             int
			wantOrderByCreatedDesc bool
		}{
			{name: "empty version orders by created_at desc", keyVersion: 0, wantOrderByCreatedDesc: true},
			{name: "explicit version does not order by created_at", keyVersion: 1, wantOrderByCreatedDesc: false},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				// given
				var captured store.ListKeyVersionsQuery
				kvs := &keyVersionStoreWrapper{}
				kvs.listKeyVersionsFn = func(_ context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
					captured = q
					return store.ListKeyVersionsResult{}, nil
				}
				c := keyprocessor.NewTestManager(nil, kvs, nil)

				// when
				_, err := c.ExportSecret(t.Context(), keyprocessor.ExportSecretRequest{
					TenantID:   uuid.NewString(),
					KeyID:      uuid.NewString(),
					KeyVersion: tc.keyVersion,
				})

				// then
				assert.ErrorIs(t, err, keyprocessor.ErrNoUsableKeyVersion)
				assert.Equal(t, tc.keyVersion, captured.Version)
				assert.Equal(t, model.KeyVersionUsable, captured.ProcessingState)
				wantOrder := []store.KeyVersionOrder{store.KeyVersionOrderRevisionDesc}
				if tc.wantOrderByCreatedDesc {
					wantOrder = []store.KeyVersionOrder{
						store.KeyVersionOrderCreatedAtDesc,
						store.KeyVersionOrderRevisionDesc,
					}
				}
				assert.Equal(t, wantOrder, captured.OrderBy)
				assert.Equal(t, 1, captured.Limit)
			})
		}
	})

	t.Run("should return error if store lookup fails", func(t *testing.T) {
		// given
		storeErr := errors.New("database unavailable")
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: tenantID, KeyID: keyID, Version: 1, ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, id, tid string) (*model.Key, error) {
			assert.Equal(t, keyID, id)
			assert.Equal(t, tenantID, tid)
			return nil, storeErr
		}
		c := keyprocessor.NewTestManager(ks, kvs, nil)

		// when
		sec, err := c.ExportSecret(t.Context(), keyprocessor.ExportSecretRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: 1,
		})

		// then
		assert.ErrorIs(t, err, storeErr)
		assert.Equal(t, cryptor.Secret{}, sec)
	})

	t.Run("should return error if key is not active", func(t *testing.T) {
		// given
		key := &model.Key{
			ID:             uuid.NewString(),
			TenantID:       uuid.NewString(),
			Kind:           "K1",
			LifeCycleState: model.KeyLifeCycleDeactivated,
		}

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: key.TenantID, KeyID: key.ID, Version: 1, ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, _, _ string) (*model.Key, error) {
			return key, nil
		}
		c := keyprocessor.NewTestManager(ks, kvs, nil)

		// when
		sec, err := c.ExportSecret(t.Context(), keyprocessor.ExportSecretRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrKeyNotActivated)
		assert.Equal(t, cryptor.Secret{}, sec)
	})

	t.Run("should return error if processor not found for key kind", func(t *testing.T) {
		// given
		key := &model.Key{
			ID:             uuid.NewString(),
			TenantID:       uuid.NewString(),
			Kind:           "UNKNOWN_KIND",
			LifeCycleState: model.KeyLifeCycleActive,
		}

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: key.TenantID, KeyID: key.ID, Version: 1, ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, _, _ string) (*model.Key, error) {
			return key, nil
		}
		c := keyprocessor.NewTestManager(ks, kvs, map[model.KeyKind]keyprocessor.Processor{})

		// when
		sec, err := c.ExportSecret(t.Context(), keyprocessor.ExportSecretRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrProcessorNotFound)
		assert.Equal(t, cryptor.Secret{}, sec)
	})

	t.Run("should succeed with explicit version", func(t *testing.T) {
		// given
		es := setupExportStack(t)
		kv := model.NewKeyVersion(es.tenantID, es.key.ID, 1, &es.rootKey.ID, nil)
		es.addKeyVersionWithSecret(t, kv)

		// when
		sec, err := es.mgr.ExportSecret(t.Context(), keyprocessor.ExportSecretRequest{
			TenantID:   es.tenantID,
			KeyID:      es.key.ID,
			KeyVersion: 1,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, sec.Data)
		assert.Equal(t, cryptor.KeyAlgorithmAES256, sec.Algorithm)
		assert.Len(t, []byte(sec.Data.SecureBytes()), 32)

		// exported material must decrypt data sealed through the manager
		sealResp, err := es.mgr.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   es.tenantID,
			KeyID:      es.key.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("sealed with manager")),
			AAD:        []byte("aad"),
		})
		require.NoError(t, err)

		decResp, err := newTestCryptor().Decrypt(t.Context(), cryptor.DecryptRequest{
			Secret:     sec,
			Ciphertext: sealResp.Ciphertext,
			AAD:        []byte("aad"),
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("sealed with manager"), []byte(decResp.Plaintext.SecureBytes()))

		// the returned secret is caller-owned and must be destroyed by the caller
		require.NoError(t, sec.Data.Destroy())
		assert.Nil(t, sec.Data.SecureBytes())
	})

	t.Run("should resolve latest version when key version is empty", func(t *testing.T) {
		// given
		es := setupExportStack(t)

		kv1 := model.NewKeyVersion(es.tenantID, es.key.ID, 1, &es.rootKey.ID, nil)
		es.addKeyVersionWithSecret(t, kv1)

		kv2 := model.NewKeyVersion(es.tenantID, es.key.ID, 2, &es.rootKey.ID, nil)
		kv2.CreatedAt = kv1.CreatedAt + 1 // strictly later than version "1"
		kv2.UpdatedAt = kv2.CreatedAt
		es.addKeyVersionWithSecret(t, kv2)

		// when
		latest := es.exportSecretBytes(t, 0)

		// then
		assert.Equal(t, es.exportSecretBytes(t, 2), latest)
		assert.NotEqual(t, es.exportSecretBytes(t, 1), latest)
	})

	t.Run("should skip non-usable versions when resolving latest", func(t *testing.T) {
		// given
		es := setupExportStack(t)

		kv1 := model.NewKeyVersion(es.tenantID, es.key.ID, 1, &es.rootKey.ID, nil)
		es.addKeyVersionWithSecret(t, kv1)

		kv2 := model.NewKeyVersion(es.tenantID, es.key.ID, 2, &es.rootKey.ID, nil)
		kv2.CreatedAt = kv1.CreatedAt + 1 // strictly later than version "1"
		kv2.UpdatedAt = kv2.CreatedAt
		es.addKeyVersionWithSecret(t, kv2)

		// version "3" is newest but not usable, so it must not be resolved
		kv3 := model.KeyVersion{
			TenantID:        es.tenantID,
			KeyID:           es.key.ID,
			Version:         3,
			Revision:        0,
			ParentKeyID:     &es.rootKey.ID,
			LifeCycleState:  model.KeyLifeCycleActive,
			ProcessingState: model.KeyVersionReWrapping,
			CreatedAt:       kv2.CreatedAt + 1,
			UpdatedAt:       kv2.CreatedAt + 1,
		}
		es.addKeyVersionWithSecret(t, kv3)

		// when
		latest := es.exportSecretBytes(t, 0)

		// then
		assert.Equal(t, es.exportSecretBytes(t, 2), latest)
	})
}

func TestGenerateAndSealSecret(t *testing.T) {
	t.Run("should generate and seal secret with manager", func(t *testing.T) {
		// given
		ps := setupParent(t)
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newTestSealer(t), ps.sealer, newTestVault(t))
		mgr := keyprocessor.NewTestManager(nil, nil, map[model.KeyKind]keyprocessor.Processor{ps.parentKey.Kind: *processor})

		childKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), 1, &ps.parentKey.ID, nil)

		// when
		resp, err := mgr.GenerateAndSealSecret(t.Context(), keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: childKV,
			AAD:        []byte{},
			KeyKind:    ps.parentKey.Kind,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.GenerateAndSealSecretResponse{}, resp)
	})
}

type exportSetup struct {
	tenantID string
	rootKey  model.Key
	key      model.Key
	kvStore  *storesql.KeyVersionStore
	proc     *keyprocessor.Processor
	mgr      *keyprocessor.Manager
}

func setupExportStack(t *testing.T) *exportSetup {
	t.Helper()
	db := createDatabase(t)
	tenantID := createTenant(t, db)
	keyStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)

	rootKey := model.NewKey(tenantID, "root-"+uuid.NewString(), "K0", nil, "test", nil)
	require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
	activateKey(t, db, rootKey)
	rootMgr := keyprocessor.NewTestRootManager(keyStore, newTestSealer(t))

	key := model.NewKey(tenantID, "exp-key-"+uuid.NewString(), "K1", &rootKey.ID, "test", nil)
	require.NoError(t, keyStore.CreateKey(t.Context(), key))
	activateKey(t, db, key)

	proc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, rootMgr, newTestVault(t))
	mgr := keyprocessor.NewTestManager(keyStore, kvStore, map[model.KeyKind]keyprocessor.Processor{key.Kind: *proc})

	return &exportSetup{
		tenantID: tenantID,
		rootKey:  rootKey,
		key:      key,
		kvStore:  kvStore,
		proc:     proc,
		mgr:      mgr,
	}
}

func (es *exportSetup) addKeyVersionWithSecret(t *testing.T, kv model.KeyVersion) {
	t.Helper()
	_, err := es.kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
	require.NoError(t, err)
	_, err = es.proc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
	require.NoError(t, err)
}

func (es *exportSetup) exportSecretBytes(t *testing.T, version int) []byte {
	t.Helper()
	sec, err := es.mgr.ExportSecret(t.Context(), keyprocessor.ExportSecretRequest{
		TenantID:   es.tenantID,
		KeyID:      es.key.ID,
		KeyVersion: version,
	})
	require.NoError(t, err)
	require.NotNil(t, sec.Data)
	material := append([]byte(nil), sec.Data.SecureBytes()...)
	require.NoError(t, sec.Data.Destroy())
	return material
}
