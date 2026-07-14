package keyprocessor_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/pkg/model"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestCreateSecret(t *testing.T) {
	t.Run("should not create if wrapper manages its own decryption key", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newStaticSecretCryptor(t), nil, nil, nil)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should return error if secret generation fails", func(t *testing.T) {
		// given
		genErr := errors.New("entropy exhausted")

		gen := &secretGenWrapper{}
		gen.generateSecretFn = func(context.Context) (*cryptor.GenerateSecretResponse, error) {
			return nil, genErr
		}
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), nil, nil, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()},
		})

		// then
		assert.ErrorIs(t, err, genErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should return error if sealing fails", func(t *testing.T) {
		// given
		sealErr := errors.New("sealing failed")

		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		var genSec *securemem.Data
		gen := &secretGenWrapper{SecretGenerator: newTestSecretGen()}
		gen.generateSecretFn = func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
			resp, err := gen.SecretGenerator.GenerateSecret(ctx)
			if err == nil {
				genSec = resp.Secret
			}
			return resp, err
		}

		sealer := &cryptorWrapper{Cryptor: newStaticSecretCryptor(t)}
		sealer.encryptFn = func(_ context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return &cryptor.EncryptResponse{}, sealErr
		}
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), sealer, nil, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: model.Key{TenantID: tenantID, ID: keyID},
		})

		// then
		assert.ErrorIs(t, err, sealErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, genSec.SecureBytes())
	})

	t.Run("should return error if parent wrapping fails", func(t *testing.T) {
		// given
		parentErr := errors.New("parent vault down")

		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		var genSec *securemem.Data
		gen := &secretGenWrapper{SecretGenerator: newTestSecretGen()}
		gen.generateSecretFn = func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
			resp, err := gen.SecretGenerator.GenerateSecret(ctx)
			if err == nil {
				genSec = resp.Secret
			}
			return resp, err
		}

		parentVault := &vaultWrapper{Vault: newTestVault(t)}
		parentVault.exportKeyFn = func(_ context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, parentKey.ID, req.KeyID)
			return nil, parentErr
		}
		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, parentVault)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), nil, parent, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: childKey,
		})

		// then
		assert.ErrorIs(t, err, parentErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, genSec.SecureBytes())
	})

	t.Run("should return error if parent wrapping fails after sealing", func(t *testing.T) {
		// given
		parentErr := errors.New("parent vault down")

		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		var genSec *securemem.Data
		gen := &secretGenWrapper{SecretGenerator: newTestSecretGen()}
		gen.generateSecretFn = func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
			resp, err := gen.SecretGenerator.GenerateSecret(ctx)
			if err == nil {
				genSec = resp.Secret
			}
			return resp, err
		}

		parentVault := &vaultWrapper{Vault: newTestVault(t)}
		parentVault.exportKeyFn = func(_ context.Context, _ vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			return nil, parentErr
		}
		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, parentVault)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		realSealer := newStaticSecretCryptor(t)
		var sealedSec *securemem.Data
		sealer := &cryptorWrapper{Cryptor: realSealer}
		sealer.encryptFn = func(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
			resp, err := realSealer.Encrypt(ctx, req)
			if err == nil {
				sealedSec = resp.Ciphertext
			}
			return resp, err
		}

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), sealer, parent, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: childKey,
		})

		// then
		assert.ErrorIs(t, err, parentErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, genSec.SecureBytes())
		assert.NotNil(t, sealedSec)
		assert.Nil(t, sealedSec.SecureBytes())
	})

	t.Run("should return error if vault import fails", func(t *testing.T) {
		// given
		importErr := errors.New("disk full")

		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		var genSec *securemem.Data
		gen := &secretGenWrapper{SecretGenerator: newTestSecretGen()}
		gen.generateSecretFn = func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
			resp, err := gen.SecretGenerator.GenerateSecret(ctx)
			if err == nil {
				genSec = resp.Secret
			}
			return resp, err
		}

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		v := &vaultWrapper{Vault: newTestVault(t)}
		v.importKeyFn = func(_ context.Context, req vault.ImportKeyRequest) (*vault.ImportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, childKey.ID, req.KeyID)
			return nil, importErr
		}
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), nil, parent, v)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: childKey,
		})

		// then
		assert.ErrorIs(t, err, importErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, genSec.SecureBytes())
	})

	t.Run("should return error if parent set but key has no parent ID", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		// Key without ParentID but processor has a parent
		orphanKey := model.Key{TenantID: tenantID, ID: uuid.NewString()}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, parent, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: orphanKey,
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrMissingParentID)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should succeed for processor with sealer", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), nil, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should succeed for processor with parent", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, parent, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: childKey,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should succeed for processor with sealer and parent", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), parent, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: childKey,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})
}

func TestResolveSecret(t *testing.T) {
	t.Run("should return nil if wrapper manages its own decryption key", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newStaticSecretCryptor(t), nil, nil, nil)

		// when
		sec, err := processor.ResolveSecret(t.Context(), model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()})

		// then
		assert.NoError(t, err)
		assert.Nil(t, sec)
	})

	t.Run("should return error if key is not found", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))

		// when
		resp, err := processor.ResolveSecret(t.Context(), model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()})

		// then
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Nil(t, resp)
	})

	t.Run("should return error if vault export fails", func(t *testing.T) {
		// given
		exportErr := errors.New("connection reset")

		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		key := model.Key{TenantID: tenantID, ID: keyID}

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		v.exportKeyFn = func(_ context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return nil, exportErr
		}

		// when
		resp, err := processor.ResolveSecret(t.Context(), key)

		// then
		assert.ErrorIs(t, err, exportErr)
		assert.Nil(t, resp)
	})

	t.Run("should return error if parent unwrap fails", func(t *testing.T) {
		// given
		parentErr := errors.New("parent unavailable")

		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentVault := &vaultWrapper{Vault: newTestVault(t)}
		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, parentVault)
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, parent, v)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		var exportSec *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exportSec = resp.KeyMaterial
			}
			return resp, err
		}
		parentVault.exportKeyFn = func(_ context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, parentKey.ID, req.KeyID)
			return nil, parentErr
		}

		// when
		resp, err := processor.ResolveSecret(t.Context(), childKey)

		// then
		assert.ErrorIs(t, err, parentErr)
		assert.Nil(t, resp)
		assert.NotNil(t, exportSec)
		assert.Nil(t, exportSec.SecureBytes())
	})

	t.Run("should return error if unsealing fails", func(t *testing.T) {
		// given
		unsealErr := errors.New("unsealing failed")

		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		key := model.Key{TenantID: tenantID, ID: keyID}

		realSealer := newStaticSecretCryptor(t)
		sealer := &cryptorWrapper{Cryptor: realSealer}
		sealer.decryptFn = func(_ context.Context, _ cryptor.DecryptRequest) (*cryptor.DecryptResponse, error) {
			return &cryptor.DecryptResponse{}, unsealErr
		}

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), sealer, nil, v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		var exportSec *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exportSec = resp.KeyMaterial
			}
			return resp, err
		}

		// when
		resp, err := processor.ResolveSecret(t.Context(), key)

		// then
		assert.ErrorIs(t, err, unsealErr)
		assert.Nil(t, resp)
		assert.NotNil(t, exportSec)
		assert.Nil(t, exportSec.SecureBytes())
	})

	t.Run("should succeed for processor with sealer", func(t *testing.T) {
		// given
		key := model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()}

		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), nil, newTestVault(t))
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		// when
		sec, err := processor.ResolveSecret(t.Context(), key)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, sec)
		assert.NotNil(t, sec.SecureBytes())
	})

	t.Run("should succeed for processor with parent", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, parent, newTestVault(t))
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		// when
		sec, err := processor.ResolveSecret(t.Context(), childKey)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, sec)
		assert.NotNil(t, sec.SecureBytes())
	})

	t.Run("should succeed for processor with sealer and parent", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), parent, newTestVault(t))
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		// when
		sec, err := processor.ResolveSecret(t.Context(), childKey)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, sec)
		assert.NotNil(t, sec.SecureBytes())
	})
}

func TestWrapSecret(t *testing.T) {
	t.Run("should return error if resolve fails", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))

		// when
		resp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()},
			Secret: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Equal(t, keyprocessor.WrapSecretResponse{}, resp)
	})

	t.Run("should return error if encryption fails", func(t *testing.T) {
		// given
		key := model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()}

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		var exportSec *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exportSec = resp.KeyMaterial
			}
			return resp, err
		}

		// when — nil plaintext is rejected by aes256gcm
		resp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    key,
			Secret: nil,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, keyprocessor.WrapSecretResponse{}, resp)
		assert.Nil(t, exportSec.SecureBytes())
	})

	t.Run("should wrap without resolving if wrapper manages its own decryption key", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newStaticSecretCryptor(t), nil, nil, nil)
		key := model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()}

		// when
		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    key,
			Secret: newTestData(t, []byte("data")),
		})
		assert.NoError(t, err)

		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           key,
			WrappedSecret: wrapResp.WrappedSecret,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("data"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for processor with sealer", func(t *testing.T) {
		// given
		key := model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()}

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), nil, v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		var exportSec *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exportSec = resp.KeyMaterial
			}
			return resp, err
		}

		// when
		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    key,
			Secret: newTestData(t, []byte("payload")),
			AAD:    []byte("aad"),
		})
		assert.NoError(t, err)

		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           key,
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
		assert.NotNil(t, exportSec)
		assert.Nil(t, exportSec.SecureBytes())
	})

	t.Run("should succeed for processor with parent", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, parent, newTestVault(t))
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		// when
		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    childKey,
			Secret: newTestData(t, []byte("payload")),
			AAD:    []byte("aad"),
		})
		assert.NoError(t, err)

		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           childKey,
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for processor with sealer and parent", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), parent, newTestVault(t))
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		// when
		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    childKey,
			Secret: newTestData(t, []byte("payload")),
			AAD:    []byte("aad"),
		})
		assert.NoError(t, err)

		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           childKey,
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})
}

func TestUnwrapSecret(t *testing.T) {
	t.Run("should return error if resolve fails", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))

		// when
		resp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()},
			WrappedSecret: newTestData(t, []byte("ciphertext")),
		})

		// then
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Equal(t, keyprocessor.UnwrapSecretResponse{}, resp)
	})

	t.Run("should return error if decryption fails with tampered ciphertext", func(t *testing.T) {
		// given
		key := model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()}

		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    key,
			Secret: newTestData(t, []byte("data")),
		})
		assert.NoError(t, err)

		original := wrapResp.WrappedSecret.SecureBytes()
		tampered := make([]byte, len(original))
		copy(tampered, original)
		tampered[0] ^= 0xFF

		// when
		resp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           key,
			WrappedSecret: newTestData(t, tampered),
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, keyprocessor.UnwrapSecretResponse{}, resp)
	})

	t.Run("should return error if decryption fails with wrong AAD", func(t *testing.T) {
		// given
		key := model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()}

		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			Key: key,
			AAD: []byte("create-aad"),
		})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    key,
			Secret: newTestData(t, []byte("data")),
			AAD:    []byte("wrap-aad"),
		})
		assert.NoError(t, err)

		// when
		resp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           key,
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("wrong-aad"),
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, keyprocessor.UnwrapSecretResponse{}, resp)
	})

	t.Run("should succeed for processor with sealer", func(t *testing.T) {
		// given
		key := model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()}

		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), nil, newTestVault(t))
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    key,
			Secret: newTestData(t, []byte("payload")),
			AAD:    []byte("aad"),
		})
		assert.NoError(t, err)

		// when
		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           key,
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for processor with parent", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, parent, newTestVault(t))
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    childKey,
			Secret: newTestData(t, []byte("payload")),
			AAD:    []byte("aad"),
		})
		assert.NoError(t, err)

		// when
		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           childKey,
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for processor with sealer and parent", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), parent, newTestVault(t))
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    childKey,
			Secret: newTestData(t, []byte("payload")),
			AAD:    []byte("aad"),
		})
		assert.NoError(t, err)

		// when
		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           childKey,
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})
}

func TestDeleteSecret(t *testing.T) {
	t.Run("should not delete if wrapper manages its own decryption key", func(t *testing.T) {
		// given
		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(nil, newStaticSecretCryptor(t), nil, nil, v)

		var called bool
		v.destroyKeyFn = func(context.Context, vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
			called = true
			return &vault.DestroyKeyResponse{}, nil
		}

		// when
		resp, err := processor.DeleteSecret(t.Context(), keyprocessor.DeleteSecretRequest{
			Key: model.Key{TenantID: uuid.NewString(), ID: uuid.NewString()},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.DeleteSecretResponse{}, resp)
		assert.False(t, called)
	})

	t.Run("should return error if key destroy fails", func(t *testing.T) {
		// given
		destroyErr := errors.New("vault locked")

		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		key := model.Key{TenantID: tenantID, ID: keyID}

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		v.destroyKeyFn = func(_ context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return nil, destroyErr
		}

		// when
		resp, err := processor.DeleteSecret(t.Context(), keyprocessor.DeleteSecretRequest{Key: key})

		// then
		assert.ErrorIs(t, err, destroyErr)
		assert.Equal(t, keyprocessor.DeleteSecretResponse{}, resp)
	})

	t.Run("should succeed", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		key := model.Key{TenantID: tenantID, ID: keyID}

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: key})
		assert.NoError(t, err)

		v.destroyKeyFn = func(ctx context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return v.Vault.DestroyKey(ctx, req)
		}

		// when
		resp, err := processor.DeleteSecret(t.Context(), keyprocessor.DeleteSecretRequest{Key: key})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.DeleteSecretResponse{}, resp)
	})
}

func TestHierarchy(t *testing.T) {
	t.Run("should succeed for two-level chain round trip", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), nil, newTestVault(t))
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		child := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, parent, newTestVault(t))
		_, err = child.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		// when
		wrapResp, err := child.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    childKey,
			Secret: newTestData(t, []byte("classified")),
		})
		assert.NoError(t, err)

		unwrapResp, err := child.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           childKey,
			WrappedSecret: wrapResp.WrappedSecret,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("classified"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for three-level chain round trip", func(t *testing.T) {
		// given
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		rootKey := model.NewKey(tenantID, "root-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))

		rootProc := keyprocessor.NewProcessor(newTestSecretGen(), newStaticSecretCryptor(t), nil, nil, newTestVault(t))
		_, err := rootProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: rootKey})
		assert.NoError(t, err)
		rootCryptor := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{rootKey.Kind: *rootProc})

		midKey := model.NewKey(tenantID, "mid-"+uuid.NewString(), "K1", &rootKey.ID, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), midKey))
		midProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newStaticSecretCryptor(t), rootCryptor, newTestVault(t))
		_, err = midProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: midKey})
		assert.NoError(t, err)
		midCryptor := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{midKey.Kind: *midProc})

		leafKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &midKey.ID, Kind: "K2"}
		leafProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, midCryptor, newTestVault(t))
		_, err = leafProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: leafKey})
		assert.NoError(t, err)

		// when
		wrapResp, err := leafProc.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    leafKey,
			Secret: newTestData(t, []byte("top secret")),
		})
		assert.NoError(t, err)

		unwrapResp, err := leafProc.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			Key:           leafKey,
			WrappedSecret: wrapResp.WrappedSecret,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("top secret"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should return error if parent vault fails during child resolve", func(t *testing.T) {
		// given
		parentErr := errors.New("parent compromised")

		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))

		parentVault := &vaultWrapper{Vault: newTestVault(t)}
		parentProc := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, nil, parentVault)
		_, err := parentProc.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: parentKey})
		assert.NoError(t, err)
		parent := keyprocessor.NewManager(keyStore, map[model.KeyKind]keyprocessor.Processor{parentKey.Kind: *parentProc})

		childKey := model.Key{TenantID: tenantID, ID: uuid.NewString(), ParentID: &parentKey.ID}
		child := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, parent, newTestVault(t))
		_, err = child.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{Key: childKey})
		assert.NoError(t, err)

		parentVault.exportKeyFn = func(context.Context, vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			return nil, parentErr
		}

		// when
		resp, err := child.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			Key:    childKey,
			Secret: newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, parentErr)
		assert.Equal(t, keyprocessor.WrapSecretResponse{}, resp)
	})
}

type vaultWrapper struct {
	vault.Vault

	importKeyFn         func(context.Context, vault.ImportKeyRequest) (*vault.ImportKeyResponse, error)
	exportKeyFn         func(context.Context, vault.ExportKeyRequest) (*vault.ExportKeyResponse, error)
	destroyKeyFn        func(context.Context, vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error)
	destroyKeyVersionFn func(context.Context, vault.DestroyKeyVersionRequest) (*vault.DestroyKeyVersionResponse, error)
	infoFn              func() vault.Info
}

func (w *vaultWrapper) ImportKey(ctx context.Context, req vault.ImportKeyRequest) (*vault.ImportKeyResponse, error) {
	if w.importKeyFn != nil {
		return w.importKeyFn(ctx, req)
	}
	return w.Vault.ImportKey(ctx, req)
}

func (w *vaultWrapper) ExportKey(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
	if w.exportKeyFn != nil {
		return w.exportKeyFn(ctx, req)
	}
	return w.Vault.ExportKey(ctx, req)
}

func (w *vaultWrapper) DestroyKey(ctx context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
	if w.destroyKeyFn != nil {
		return w.destroyKeyFn(ctx, req)
	}
	return w.Vault.DestroyKey(ctx, req)
}

func (w *vaultWrapper) DestroyKeyVersion(ctx context.Context, req vault.DestroyKeyVersionRequest) (*vault.DestroyKeyVersionResponse, error) {
	if w.destroyKeyVersionFn != nil {
		return w.destroyKeyVersionFn(ctx, req)
	}
	return w.Vault.DestroyKeyVersion(ctx, req)
}

func (w *vaultWrapper) Info() vault.Info {
	if w.infoFn != nil {
		return w.infoFn()
	}
	return w.Vault.Info()
}

type secretGenWrapper struct {
	cryptor.SecretGenerator

	generateSecretFn func(context.Context) (*cryptor.GenerateSecretResponse, error)
}

func (w *secretGenWrapper) GenerateSecret(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
	if w.generateSecretFn != nil {
		return w.generateSecretFn(ctx)
	}
	return w.SecretGenerator.GenerateSecret(ctx)
}

type cryptorWrapper struct {
	cryptor.Cryptor

	encryptFn func(context.Context, cryptor.EncryptRequest) (*cryptor.EncryptResponse, error)
	decryptFn func(context.Context, cryptor.DecryptRequest) (*cryptor.DecryptResponse, error)
	infoFn    func() cryptor.Info
}

func (w *cryptorWrapper) Encrypt(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
	if w.encryptFn != nil {
		return w.encryptFn(ctx, req)
	}
	return w.Cryptor.Encrypt(ctx, req)
}

func (w *cryptorWrapper) Decrypt(ctx context.Context, req cryptor.DecryptRequest) (*cryptor.DecryptResponse, error) {
	if w.decryptFn != nil {
		return w.decryptFn(ctx, req)
	}
	return w.Cryptor.Decrypt(ctx, req)
}

func (w *cryptorWrapper) Info() cryptor.Info {
	if w.infoFn != nil {
		return w.infoFn()
	}
	return w.Cryptor.Info()
}

func newTestVault(t *testing.T) *sqlitevault.Unsafe {
	t.Helper()
	v, err := sqlitevault.NewUnsafe(t.Context(), "test", sqlitevault.MemorySource)
	assert.NoError(t, err)
	t.Cleanup(func() { _ = v.Close() })
	return v
}

func newTestCryptor() *aes256gcm.AES256GCM {
	return aes256gcm.New("test")
}

func newTestSecretGen() *cryptor.AES256SecretGenerator {
	return cryptor.NewAES256SecretGenerator()
}

func newStaticSecretCryptor(t *testing.T) *staticsecret.StaticSecret {
	t.Helper()
	key, err := securemem.NewData("static-key", 32)
	assert.NoError(t, err)
	_, err = rand.Read(key.SecureBytes())
	assert.NoError(t, err)
	t.Cleanup(func() { _ = key.Destroy() })
	c, err := staticsecret.New("test-static", key)
	assert.NoError(t, err)
	return c
}

func newTestData(t *testing.T, content []byte) *securemem.Data {
	t.Helper()
	d, err := securemem.NewData("test", len(content))
	assert.NoError(t, err)
	copy(d.SecureBytes(), content)
	return d
}
