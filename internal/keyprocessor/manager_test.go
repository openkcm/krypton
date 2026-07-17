package keyprocessor_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestManagerEncrypt(t *testing.T) {
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
		c := keyprocessor.NewManager(nil, kvs, nil)

		// when
		resp, err := c.Encrypt(t.Context(), cryptor.EncryptRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, kvStoreErr)
		assert.Nil(t, resp)
	})

	t.Run("should return error if no usable key version found", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{KeyVersions: []model.KeyVersion{}}, nil
		}
		c := keyprocessor.NewManager(nil, kvs, nil)

		// when
		resp, err := c.Encrypt(t.Context(), cryptor.EncryptRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrNoUsableKeyVersion)
		assert.Nil(t, resp)
	})

	t.Run("should return error if store lookup fails", func(t *testing.T) {
		// given
		storeErr := errors.New("database unavailable")
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: tenantID, KeyID: keyID, Version: "1", ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, id, tid string) (*model.Key, error) {
			assert.Equal(t, keyID, id)
			assert.Equal(t, tenantID, tid)
			return nil, storeErr
		}
		c := keyprocessor.NewManager(ks, kvs, nil)

		// when
		resp, err := c.Encrypt(t.Context(), cryptor.EncryptRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, storeErr)
		assert.Nil(t, resp)
	})

	t.Run("should return error if processor not found for key kind", func(t *testing.T) {
		// given
		key := &model.Key{
			ID:       uuid.NewString(),
			TenantID: uuid.NewString(),
			Kind:     "UNKNOWN_KIND",
		}

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: key.TenantID, KeyID: key.ID, Version: "1", ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, id, tid string) (*model.Key, error) {
			assert.Equal(t, key.ID, id)
			assert.Equal(t, key.TenantID, tid)
			return key, nil
		}
		c := keyprocessor.NewManager(ks, kvs, map[model.KeyKind]keyprocessor.Processor{})

		// when
		resp, err := c.Encrypt(t.Context(), cryptor.EncryptRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: "1",
			Plaintext:  newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrProcessorNotFound)
		assert.Nil(t, resp)
	})

	t.Run("should succeed", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		key := model.NewKey(tenantID, "enc-key-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), key))

		kv := model.NewKeyVersion(tenantID, key.ID, "1", nil, nil)
		_, err := kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
		require.NoError(t, err)

		proc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err = proc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
		assert.NoError(t, err)

		c := keyprocessor.NewManager(keyStore, kvStore, map[model.KeyKind]keyprocessor.Processor{key.Kind: *proc})

		// when
		resp, err := c.Encrypt(t.Context(), cryptor.EncryptRequest{
			TenantID:   tenantID,
			KeyID:      key.ID,
			KeyVersion: "1",
			Plaintext:  newTestData(t, []byte("secret payload")),
			AAD:        []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.Ciphertext)
		assert.NotEmpty(t, resp.Ciphertext.SecureBytes())
	})
}

func TestManagerDecrypt(t *testing.T) {
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
		c := keyprocessor.NewManager(nil, kvs, nil)

		// when
		resp, err := c.Decrypt(t.Context(), cryptor.DecryptRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
			Ciphertext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, kvStoreErr)
		assert.Nil(t, resp)
	})

	t.Run("should return error if store lookup fails", func(t *testing.T) {
		// given
		storeErr := errors.New("database unavailable")
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: tenantID, KeyID: keyID, Version: "1", ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, id, tid string) (*model.Key, error) {
			assert.Equal(t, keyID, id)
			assert.Equal(t, tenantID, tid)
			return nil, storeErr
		}
		c := keyprocessor.NewManager(ks, kvs, nil)

		// when
		resp, err := c.Decrypt(t.Context(), cryptor.DecryptRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
			Ciphertext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, storeErr)
		assert.Nil(t, resp)
	})

	t.Run("should return error if processor not found for key kind", func(t *testing.T) {
		// given
		key := &model.Key{
			ID:       uuid.NewString(),
			TenantID: uuid.NewString(),
			Kind:     "UNKNOWN_KIND",
		}

		kvs := &keyVersionStoreWrapper{}
		kvs.listKeyVersionsFn = func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
			return store.ListKeyVersionsResult{
				KeyVersions: []model.KeyVersion{{TenantID: key.TenantID, KeyID: key.ID, Version: "1", ProcessingState: model.KeyVersionUsable}},
			}, nil
		}
		ks := &keyStoreWrapper{}
		ks.getKeyByIDFn = func(_ context.Context, id, tid string) (*model.Key, error) {
			assert.Equal(t, key.ID, id)
			assert.Equal(t, key.TenantID, tid)
			return key, nil
		}
		c := keyprocessor.NewManager(ks, kvs, map[model.KeyKind]keyprocessor.Processor{})

		// when
		resp, err := c.Decrypt(t.Context(), cryptor.DecryptRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: "1",
			Ciphertext: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrProcessorNotFound)
		assert.Nil(t, resp)
	})

	t.Run("should succeed with round trip", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		key := model.NewKey(tenantID, "dec-key-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), key))

		kv := model.NewKeyVersion(tenantID, key.ID, "1", nil, nil)
		_, err := kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
		require.NoError(t, err)

		proc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err = proc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
		assert.NoError(t, err)

		c := keyprocessor.NewManager(keyStore, kvStore, map[model.KeyKind]keyprocessor.Processor{key.Kind: *proc})

		encResp, err := c.Encrypt(t.Context(), cryptor.EncryptRequest{
			TenantID:   tenantID,
			KeyID:      key.ID,
			KeyVersion: "1",
			Plaintext:  newTestData(t, []byte("round trip data")),
			AAD:        []byte("aad"),
		})
		assert.NoError(t, err)

		// when
		decResp, err := c.Decrypt(t.Context(), cryptor.DecryptRequest{
			TenantID:   tenantID,
			KeyID:      key.ID,
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
			AAD:        []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, decResp)
		assert.Equal(t, []byte("round trip data"), []byte(decResp.Plaintext.SecureBytes()))
	})
}

func TestManagerInfo(t *testing.T) {
	t.Run("should return manager info with decryption secret required", func(t *testing.T) {
		// given
		c := keyprocessor.NewManager(nil, nil, nil)

		// when
		info := c.Info()

		// then
		assert.Equal(t, cryptor.Info{
			Name:                     "keyprocessor-manager",
			Type:                     keyprocessor.TypeManager,
			DecryptionSecretRequired: true,
		}, info)
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
