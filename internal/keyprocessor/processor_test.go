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

type parentSetup struct {
	tenantID  string
	parentKey model.Key
	sealer    *sealerWrapper // exposed for error injection in tests
}

func setupParent(t *testing.T) *parentSetup {
	t.Helper()
	db := createDatabase(t)
	tenantID := createTenant(t, db)
	keyStore := storesql.NewKeyStore(db)

	parentKey := model.NewKey(tenantID, "parent-"+uuid.NewString(), "K0", nil, "test", nil)
	require.NoError(t, keyStore.CreateKey(t.Context(), parentKey))
	activateKey(t, db, parentKey)

	rootMgr := keyprocessor.NewTestRootManager(keyStore, newTestSealer(t))
	sw := &sealerWrapper{Sealer: rootMgr}

	return &parentSetup{
		tenantID:  tenantID,
		parentKey: parentKey,
		sealer:    sw,
	}
}

func TestCreateSecret(t *testing.T) {
	t.Run("should return error if secret generation fails", func(t *testing.T) {
		// given
		genErr := errors.New("entropy exhausted")

		gen := &secretGenWrapper{}
		gen.generateSecretFn = func(context.Context) (*cryptor.GenerateSecretResponse, error) {
			return nil, genErr
		}
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), nil, newTestSealer(t), newTestVault(t))

		parentKeyID := uuid.NewString()
		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyVersion: model.NewKeyVersion(uuid.NewString(), uuid.NewString(), "1", &parentKeyID, nil),
		})

		// then
		assert.ErrorIs(t, err, genErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should return error if transport sealing fails", func(t *testing.T) {
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

		sealer := &sealerWrapper{Sealer: newTestSealer(t)}
		sealer.sealFn = func(_ context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return cryptor.SealResponse{}, sealErr
		}
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), sealer, newTestSealer(t), newTestVault(t))

		parentKeyID := uuid.NewString()
		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyVersion: model.NewKeyVersion(tenantID, keyID, "1", &parentKeyID, nil),
		})

		// then
		assert.ErrorIs(t, err, sealErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, genSec.SecureBytes())
	})

	t.Run("should return error if parent sealing fails", func(t *testing.T) {
		// given
		parentErr := errors.New("parent vault down")
		ps := setupParent(t)
		ps.sealer.sealFn = func(_ context.Context, _ cryptor.SealRequest) (cryptor.SealResponse, error) {
			return cryptor.SealResponse{}, parentErr
		}

		var genSec *securemem.Data
		gen := &secretGenWrapper{SecretGenerator: newTestSecretGen()}
		gen.generateSecretFn = func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
			resp, err := gen.SecretGenerator.GenerateSecret(ctx)
			if err == nil {
				genSec = resp.Secret
			}
			return resp, err
		}

		childKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), "1", &ps.parentKey.ID, nil)
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), nil, ps.sealer, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyVersion: childKV,
		})

		// then
		assert.ErrorIs(t, err, parentErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, genSec.SecureBytes())
	})

	t.Run("should return error if parent sealing fails after transport sealing", func(t *testing.T) {
		// given
		parentErr := errors.New("parent vault down")
		ps := setupParent(t)
		ps.sealer.sealFn = func(_ context.Context, _ cryptor.SealRequest) (cryptor.SealResponse, error) {
			return cryptor.SealResponse{}, parentErr
		}

		var genSec *securemem.Data
		gen := &secretGenWrapper{SecretGenerator: newTestSecretGen()}
		gen.generateSecretFn = func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
			resp, err := gen.SecretGenerator.GenerateSecret(ctx)
			if err == nil {
				genSec = resp.Secret
			}
			return resp, err
		}

		realSealer := newTestSealer(t)
		var sealedSec *securemem.Data
		sealer := &sealerWrapper{Sealer: realSealer}
		sealer.sealFn = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			resp, err := realSealer.Seal(ctx, req)
			if err == nil {
				sealedSec = resp.Ciphertext
			}
			return resp, err
		}

		childKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), "1", &ps.parentKey.ID, nil)
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), sealer, ps.sealer, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyVersion: childKV,
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
		ps := setupParent(t)

		var genSec *securemem.Data
		gen := &secretGenWrapper{SecretGenerator: newTestSecretGen()}
		gen.generateSecretFn = func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
			resp, err := gen.SecretGenerator.GenerateSecret(ctx)
			if err == nil {
				genSec = resp.Secret
			}
			return resp, err
		}

		childKeyID := uuid.NewString()
		childKV := model.NewKeyVersion(ps.tenantID, childKeyID, "1", &ps.parentKey.ID, nil)
		v := &vaultWrapper{Vault: newTestVault(t)}
		v.importKeyFn = func(_ context.Context, req vault.ImportKeyRequest) (*vault.ImportKeyResponse, error) {
			assert.Equal(t, ps.tenantID, req.TenantID)
			assert.Equal(t, childKeyID, req.KeyID)
			return nil, importErr
		}
		processor := keyprocessor.NewProcessor(gen, newTestCryptor(), nil, ps.sealer, v)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyVersion: childKV,
		})

		// then
		assert.ErrorIs(t, err, importErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, genSec.SecureBytes())
	})

	t.Run("should return error if parent set but key version has no parent key version", func(t *testing.T) {
		// given
		ps := setupParent(t)
		orphanKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), "1", nil, nil)
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, ps.sealer, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyVersion: orphanKV,
		})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrMissingParentKey)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should succeed", func(t *testing.T) {
		// given
		ps := setupParent(t)
		childKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), "1", &ps.parentKey.ID, nil)
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, ps.sealer, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyVersion: childKV,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should succeed with transport sealer", func(t *testing.T) {
		// given
		ps := setupParent(t)
		childKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), "1", &ps.parentKey.ID, nil)
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newTestSealer(t), ps.sealer, newTestVault(t))

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyVersion: childKV,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})
}

func TestResolveSecret(t *testing.T) {
	t.Run("should return error if key is not found", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, newTestSealer(t), newTestVault(t))

		parentKeyID := uuid.NewString()
		// when
		sec, err := processor.ResolveSecret(t.Context(), model.NewKeyVersion(uuid.NewString(), uuid.NewString(), "1", &parentKeyID, nil))

		// then
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Equal(t, cryptor.Secret{}, sec)
	})

	t.Run("should return error if vault export fails", func(t *testing.T) {
		// given
		exportErr := errors.New("connection reset")

		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentKeyID := uuid.NewString()
		kv := model.NewKeyVersion(tenantID, keyID, "1", &parentKeyID, nil)

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, newTestSealer(t), v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
		assert.NoError(t, err)

		v.exportKeyFn = func(_ context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return nil, exportErr
		}

		// when
		sec, err := processor.ResolveSecret(t.Context(), kv)

		// then
		assert.ErrorIs(t, err, exportErr)
		assert.Equal(t, cryptor.Secret{}, sec)
	})

	t.Run("should return error if parent unsealing fails", func(t *testing.T) {
		// given
		parentErr := errors.New("parent unavailable")
		ps := setupParent(t)

		childKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), "1", &ps.parentKey.ID, nil)
		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, ps.sealer, v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: childKV})
		assert.NoError(t, err)

		var exportSec *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exportSec = resp.KeyMaterial
			}
			return resp, err
		}
		ps.sealer.unsealFn = func(_ context.Context, _ cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			return cryptor.UnsealResponse{}, parentErr
		}

		// when
		sec, err := processor.ResolveSecret(t.Context(), childKV)

		// then
		assert.ErrorIs(t, err, parentErr)
		assert.Equal(t, cryptor.Secret{}, sec)
		assert.NotNil(t, exportSec)
		assert.Nil(t, exportSec.SecureBytes())
	})

	t.Run("should return error if transport unsealing fails", func(t *testing.T) {
		// given
		unsealErr := errors.New("unsealing failed")

		parentKeyID := uuid.NewString()
		kv := model.NewKeyVersion(uuid.NewString(), uuid.NewString(), "1", &parentKeyID, nil)

		realSealer := newTestSealer(t)
		sealer := &sealerWrapper{Sealer: realSealer}
		sealer.unsealFn = func(_ context.Context, _ cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			return cryptor.UnsealResponse{}, unsealErr
		}

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), sealer, newTestSealer(t), v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
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
		sec, err := processor.ResolveSecret(t.Context(), kv)

		// then
		assert.ErrorIs(t, err, unsealErr)
		assert.Equal(t, cryptor.Secret{}, sec)
		assert.NotNil(t, exportSec)
		assert.Nil(t, exportSec.SecureBytes())
	})

	t.Run("should succeed", func(t *testing.T) {
		// given
		ps := setupParent(t)
		childKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), "1", &ps.parentKey.ID, nil)
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, ps.sealer, newTestVault(t))
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: childKV})
		assert.NoError(t, err)

		// when
		sec, err := processor.ResolveSecret(t.Context(), childKV)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, sec.Data)
		assert.NotEmpty(t, sec.Data.SecureBytes())
		assert.Equal(t, cryptor.KeyAlgorithmAES256, sec.Algorithm)
	})

	t.Run("should succeed with transport sealer", func(t *testing.T) {
		// given
		ps := setupParent(t)
		childKV := model.NewKeyVersion(ps.tenantID, uuid.NewString(), "1", &ps.parentKey.ID, nil)
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), newTestSealer(t), ps.sealer, newTestVault(t))
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: childKV})
		assert.NoError(t, err)

		// when
		sec, err := processor.ResolveSecret(t.Context(), childKV)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, sec.Data)
		assert.NotEmpty(t, sec.Data.SecureBytes())
		assert.Equal(t, cryptor.KeyAlgorithmAES256, sec.Algorithm)
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("should return error if plaintext is nil", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newTestCryptor(), nil, nil, nil)

		// when
		resp, err := processor.Encrypt(t.Context(), cryptor.EncryptRequest{
			Secret:    newTestSecret(t),
			Plaintext: nil,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should encrypt and decrypt round trip", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newTestCryptor(), nil, nil, nil)
		sec := newTestSecret(t)

		// when
		encResp, err := processor.Encrypt(t.Context(), cryptor.EncryptRequest{
			Secret:    sec,
			Plaintext: newTestData(t, []byte("hello")),
		})
		assert.NoError(t, err)

		decResp, err := processor.Decrypt(t.Context(), cryptor.DecryptRequest{
			Secret:     sec,
			Ciphertext: encResp.Ciphertext,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("hello"), []byte(decResp.Plaintext.SecureBytes()))
	})

	t.Run("should encrypt and decrypt round trip with AAD", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newTestCryptor(), nil, nil, nil)
		sec := newTestSecret(t)

		// when
		encResp, err := processor.Encrypt(t.Context(), cryptor.EncryptRequest{
			Secret:    sec,
			Plaintext: newTestData(t, []byte("payload")),
			AAD:       []byte("aad"),
		})
		assert.NoError(t, err)

		decResp, err := processor.Decrypt(t.Context(), cryptor.DecryptRequest{
			Secret:     sec,
			Ciphertext: encResp.Ciphertext,
			AAD:        []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(decResp.Plaintext.SecureBytes()))
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("should return error with tampered ciphertext", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newTestCryptor(), nil, nil, nil)
		sec := newTestSecret(t)

		encResp, err := processor.Encrypt(t.Context(), cryptor.EncryptRequest{
			Secret:    sec,
			Plaintext: newTestData(t, []byte("data")),
		})
		assert.NoError(t, err)

		original := encResp.Ciphertext.SecureBytes()
		tampered := make([]byte, len(original))
		copy(tampered, original)
		tampered[0] ^= 0xFF

		// when
		resp, err := processor.Decrypt(t.Context(), cryptor.DecryptRequest{
			Secret:     sec,
			Ciphertext: newTestData(t, tampered),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should return error with wrong AAD", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newTestCryptor(), nil, nil, nil)
		sec := newTestSecret(t)

		encResp, err := processor.Encrypt(t.Context(), cryptor.EncryptRequest{
			Secret:    sec,
			Plaintext: newTestData(t, []byte("data")),
			AAD:       []byte("correct-aad"),
		})
		assert.NoError(t, err)

		// when
		resp, err := processor.Decrypt(t.Context(), cryptor.DecryptRequest{
			Secret:     sec,
			Ciphertext: encResp.Ciphertext,
			AAD:        []byte("wrong-aad"),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should return error if ciphertext is nil", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor(nil, newTestCryptor(), nil, nil, nil)

		// when
		resp, err := processor.Decrypt(t.Context(), cryptor.DecryptRequest{
			Secret:     newTestSecret(t),
			Ciphertext: nil,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})
}

func TestDeleteSecret(t *testing.T) {
	t.Run("should return error if key destroy fails", func(t *testing.T) {
		// given
		destroyErr := errors.New("vault locked")

		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentKeyID := uuid.NewString()
		kv := model.NewKeyVersion(tenantID, keyID, "1", &parentKeyID, nil)

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, newTestSealer(t), v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
		assert.NoError(t, err)

		v.destroyKeyFn = func(_ context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return nil, destroyErr
		}

		// when
		resp, err := processor.DeleteSecret(t.Context(), keyprocessor.DeleteSecretRequest{KeyVersion: kv})

		// then
		assert.ErrorIs(t, err, destroyErr)
		assert.Equal(t, keyprocessor.DeleteSecretResponse{}, resp)
	})

	t.Run("should succeed", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentKeyID := uuid.NewString()
		kv := model.NewKeyVersion(tenantID, keyID, "1", &parentKeyID, nil)

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor(newTestSecretGen(), newTestCryptor(), nil, newTestSealer(t), v)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{KeyVersion: kv})
		assert.NoError(t, err)

		v.destroyKeyFn = func(ctx context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return v.Vault.DestroyKey(ctx, req)
		}

		// when
		resp, err := processor.DeleteSecret(t.Context(), keyprocessor.DeleteSecretRequest{KeyVersion: kv})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.DeleteSecretResponse{}, resp)
	})
}

type vaultWrapper struct {
	vault.Vault

	importKeyFn  func(context.Context, vault.ImportKeyRequest) (*vault.ImportKeyResponse, error)
	exportKeyFn  func(context.Context, vault.ExportKeyRequest) (*vault.ExportKeyResponse, error)
	destroyKeyFn func(context.Context, vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error)
	infoFn       func() vault.Info
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

type sealerWrapper struct {
	cryptor.Sealer

	sealFn   func(context.Context, cryptor.SealRequest) (cryptor.SealResponse, error)
	unsealFn func(context.Context, cryptor.UnsealRequest) (cryptor.UnsealResponse, error)
}

func (w *sealerWrapper) Seal(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
	if w.sealFn != nil {
		return w.sealFn(ctx, req)
	}
	return w.Sealer.Seal(ctx, req)
}

func (w *sealerWrapper) Unseal(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
	if w.unsealFn != nil {
		return w.unsealFn(ctx, req)
	}
	return w.Sealer.Unseal(ctx, req)
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

func newTestSealer(t *testing.T) *staticsecret.StaticSecret {
	t.Helper()
	key, err := securemem.NewData("static-key", 32)
	assert.NoError(t, err)
	_, err = rand.Read(key.SecureBytes())
	assert.NoError(t, err)
	t.Cleanup(func() { _ = key.Destroy() })
	s, err := staticsecret.New("test-static", key)
	assert.NoError(t, err)
	return s
}

func newTestSecret(t *testing.T) cryptor.Secret {
	t.Helper()
	key, err := securemem.NewData("test-key", 32)
	assert.NoError(t, err)
	_, err = rand.Read(key.SecureBytes())
	assert.NoError(t, err)
	t.Cleanup(func() { _ = key.Destroy() })
	return cryptor.Secret{
		Algorithm: cryptor.KeyAlgorithmAES256,
		Data:      key,
	}
}

func newTestData(t *testing.T, content []byte) *securemem.Data {
	t.Helper()
	d, err := securemem.NewData("test", len(content))
	assert.NoError(t, err)
	copy(d.SecureBytes(), content)
	return d
}
