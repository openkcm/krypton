package keyprocessor_test

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/pkg/model"
)

func TestCreateSecret(t *testing.T) {
	t.Run("should not create if cryptor manages its own decryption key", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor("", newTestVault(t), newStaticSecretCryptor(t), newTestSecretGen(), nil, nil)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: uuid.NewString(), ID: uuid.NewString()}},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should return error if key chain is empty", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrEmptyKeyChain)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should return error if secret generation fails", func(t *testing.T) {
		// given
		genErr := errors.New("entropy exhausted")
		gen := &secretGenWrapper{
			generateSecretFn: func(context.Context) (*cryptor.GenerateSecretResponse, error) {
				return nil, genErr
			},
		}
		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), gen, nil, nil)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: uuid.NewString(), ID: uuid.NewString()}},
		})

		// then
		assert.ErrorIs(t, err, genErr)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should return error if internal wrap fails", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		var captured *securemem.Data
		realGen := newTestSecretGen()
		gen := &secretGenWrapper{
			generateSecretFn: func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
				resp, err := realGen.GenerateSecret(ctx)
				if err == nil {
					captured = resp.Secret
				}
				return resp, err
			},
		}

		internalVault := &vaultWrapper{Vault: newTestVault(t)}
		internalVault.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, "internal/"+keyID, req.KeyID)
			return nil, errors.New("internal export failed")
		}
		internal := keyprocessor.NewProcessor("internal", internalVault, newTestCryptor(), newTestSecretGen(), nil, nil)
		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), gen, internal, nil)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})

		// then
		assert.ErrorContains(t, err, "internal export failed")
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, captured.SecureBytes())
	})

	t.Run("should return error if parent wrap fails", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		var captured *securemem.Data
		realGen := newTestSecretGen()
		gen := &secretGenWrapper{
			generateSecretFn: func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
				resp, err := realGen.GenerateSecret(ctx)
				if err == nil {
					captured = resp.Secret
				}
				return resp, err
			},
		}

		parentVault := &vaultWrapper{Vault: newTestVault(t)}
		parentVault.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, parentID, req.KeyID)
			return nil, errors.New("parent vault down")
		}
		parent := keyprocessor.NewProcessor("", parentVault, newTestCryptor(), newTestSecretGen(), nil, nil)
		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), gen, nil, parent)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})

		// then
		assert.ErrorContains(t, err, "parent vault down")
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, captured.SecureBytes())
	})

	t.Run("should return error if parent wrap fails after internal wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		var captured *securemem.Data
		realGen := newTestSecretGen()
		gen := &secretGenWrapper{
			generateSecretFn: func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
				resp, err := realGen.GenerateSecret(ctx)
				if err == nil {
					captured = resp.Secret
				}
				return resp, err
			},
		}

		parentVault := &vaultWrapper{Vault: newTestVault(t)}
		parentVault.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			return nil, errors.New("parent vault down")
		}
		parent := keyprocessor.NewProcessor("", parentVault, newTestCryptor(), newTestSecretGen(), nil, nil)

		var internalWrapOutput *securemem.Data
		internalCryptor := &cryptorWrapper{
			Cryptor: newTestCryptor(),
			encryptFn: func(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
				resp, err := newTestCryptor().Encrypt(ctx, req)
				if err == nil {
					internalWrapOutput = resp.Ciphertext
				}
				return resp, err
			},
		}
		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, internalCryptor, newTestSecretGen(), nil, nil)
		_, err := internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), gen, internal, parent)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})

		// then
		assert.ErrorContains(t, err, "parent vault down")
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, captured.SecureBytes())
		assert.NotNil(t, internalWrapOutput)
		assert.Nil(t, internalWrapOutput.SecureBytes())
	})

	t.Run("should return error if vault import fails", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		var captured *securemem.Data
		realGen := newTestSecretGen()
		gen := &secretGenWrapper{
			generateSecretFn: func(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
				resp, err := realGen.GenerateSecret(ctx)
				if err == nil {
					captured = resp.Secret
				}
				return resp, err
			},
		}

		parentV := newTestVault(t)
		parentInternal := keyprocessor.NewProcessor("internal", parentV, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parentInternal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)
		parent := keyprocessor.NewProcessor("", parentV, newTestCryptor(), newTestSecretGen(), parentInternal, nil)
		_, err = parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		v := &vaultWrapper{Vault: newTestVault(t)}
		v.importKeyFn = func(ctx context.Context, req vault.ImportKeyRequest) (*vault.ImportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return nil, errors.New("disk full")
		}
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), gen, nil, parent)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})

		// then
		assert.ErrorContains(t, err, "disk full")
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
		assert.Nil(t, captured.SecureBytes())
	})

	t.Run("should succeed for processor with internal wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, nil)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should succeed for processor with parent wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parent := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, parent)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})

	t.Run("should succeed for processor with internal and parent wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parent := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err = internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, parent)

		// when
		resp, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.CreateSecretResponse{}, resp)
	})
}

func TestResolveSecret(t *testing.T) {
	t.Run("should return nil if cryptor manages its own decryption key", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor("", newTestVault(t), newStaticSecretCryptor(t), newTestSecretGen(), nil, nil)

		// when
		sec, err := processor.ResolveSecret(t.Context(), []model.Key{{TenantID: uuid.NewString(), ID: uuid.NewString()}})

		// then
		assert.NoError(t, err)
		assert.Nil(t, sec)
	})

	t.Run("should return error if key chain is empty", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)

		// when
		resp, err := processor.ResolveSecret(t.Context(), []model.Key{})

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrEmptyKeyChain)
		assert.Nil(t, resp)
	})

	t.Run("should return error if key is not found", func(t *testing.T) {
		// given
		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, nil)

		// when
		resp, err := processor.ResolveSecret(t.Context(), []model.Key{{TenantID: uuid.NewString(), ID: uuid.NewString()}})

		// then
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Nil(t, resp)
	})

	t.Run("should return error if vault export fails", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		v := &vaultWrapper{Vault: newTestVault(t)}
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return nil, errors.New("connection reset")
		}
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		// when
		resp, err := processor.ResolveSecret(t.Context(), []model.Key{{TenantID: tenantID, ID: keyID}})

		// then
		assert.ErrorContains(t, err, "connection reset")
		assert.Nil(t, resp)
	})

	t.Run("should return error if parent unwrap fails", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parentVault := &vaultWrapper{Vault: newTestVault(t)}
		parent := keyprocessor.NewProcessor("", parentVault, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), nil, parent)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		var exported *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exported = resp.KeyMaterial
			}
			return resp, err
		}
		parentVault.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, parentID, req.KeyID)
			return nil, errors.New("parent unavailable")
		}

		// when
		resp, err := processor.ResolveSecret(t.Context(), []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}})

		// then
		assert.ErrorContains(t, err, "parent unavailable")
		assert.Nil(t, resp)
		assert.NotNil(t, exported)
		assert.Nil(t, exported.SecureBytes())
	})

	t.Run("should return error if internal unwrap fails", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		internalVault := &vaultWrapper{Vault: newTestVault(t)}
		internal := keyprocessor.NewProcessor("internal", internalVault, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, nil)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		var exported *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exported = resp.KeyMaterial
			}
			return resp, err
		}
		internalVault.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, "internal/"+keyID, req.KeyID)
			return nil, errors.New("internal export failed")
		}

		// when
		resp, err := processor.ResolveSecret(t.Context(), []model.Key{{TenantID: tenantID, ID: keyID}})

		// then
		assert.ErrorContains(t, err, "internal export failed")
		assert.Nil(t, resp)
		assert.NotNil(t, exported)
		assert.Nil(t, exported.SecureBytes())
	})

	t.Run("should succeed for processor with internal wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, nil)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		// when
		sec, err := processor.ResolveSecret(t.Context(), []model.Key{{TenantID: tenantID, ID: keyID}})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, sec)
		assert.NotNil(t, sec.SecureBytes())
	})

	t.Run("should succeed for processor with parent wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parent := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, parent)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		// when
		sec, err := processor.ResolveSecret(t.Context(), []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, sec)
		assert.NotNil(t, sec.SecureBytes())
	})

	t.Run("should succeed for processor with internal and parent wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parent := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err = internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, parent)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		// when
		sec, err := processor.ResolveSecret(t.Context(), []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, sec)
		assert.NotNil(t, sec.SecureBytes())
	})
}

func TestWrapSecret(t *testing.T) {
	t.Run("should return error if resolve fails", func(t *testing.T) {
		// given
		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, nil)

		// when
		resp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: uuid.NewString(), ID: uuid.NewString()}},
			Secret:   newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Equal(t, keyprocessor.WrapSecretResponse{}, resp)
	})

	t.Run("should return error if encryption fails", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		v := &vaultWrapper{Vault: newTestVault(t)}
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, nil)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		var exported *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exported = resp.KeyMaterial
			}
			return resp, err
		}

		// when — nil plaintext is rejected by aes256gcm
		resp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
			Secret:   nil,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, keyprocessor.WrapSecretResponse{}, resp)
		assert.Nil(t, exported.SecureBytes())
	})

	t.Run("should wrap without resolving if cryptor manages its own decryption key", func(t *testing.T) {
		// given
		processor := keyprocessor.NewProcessor("", newTestVault(t), newStaticSecretCryptor(t), newTestSecretGen(), nil, nil)

		// when
		chain := []model.Key{{TenantID: uuid.NewString(), ID: uuid.NewString()}}
		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: chain,
			Secret:   newTestData(t, []byte("data")),
		})
		assert.NoError(t, err)

		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      chain,
			WrappedSecret: wrapResp.WrappedSecret,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("data"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for processor with internal wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		v := &vaultWrapper{Vault: newTestVault(t)}
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, nil)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		var exported *securemem.Data
		v.exportKeyFn = func(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			resp, err := v.Vault.ExportKey(ctx, req)
			if err == nil {
				exported = resp.KeyMaterial
			}
			return resp, err
		}

		// when
		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
			Secret:   newTestData(t, []byte("payload")),
			AAD:      []byte("aad"),
		})
		assert.NoError(t, err)

		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: tenantID, ID: keyID}},
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
		assert.NotNil(t, exported)
		assert.Nil(t, exported.SecureBytes())
	})

	t.Run("should succeed for processor with parent wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parent := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, parent)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		// when
		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
			Secret:   newTestData(t, []byte("payload")),
			AAD:      []byte("aad"),
		})
		assert.NoError(t, err)

		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for processor with internal and parent wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parent := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err = internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, parent)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		// when
		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
			Secret:   newTestData(t, []byte("payload")),
			AAD:      []byte("aad"),
		})
		assert.NoError(t, err)

		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
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
		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)

		// when
		resp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: uuid.NewString(), ID: uuid.NewString()}},
			WrappedSecret: newTestData(t, []byte("ciphertext")),
		})

		// then
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Equal(t, keyprocessor.UnwrapSecretResponse{}, resp)
	})

	t.Run("should return error if decryption fails with tampered ciphertext", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
			Secret:   newTestData(t, []byte("data")),
		})
		assert.NoError(t, err)

		original := wrapResp.WrappedSecret.SecureBytes()
		tampered := make([]byte, len(original))
		copy(tampered, original)
		tampered[0] ^= 0xFF

		// when
		resp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: tenantID, ID: keyID}},
			WrappedSecret: newTestData(t, tampered),
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, keyprocessor.UnwrapSecretResponse{}, resp)
	})

	t.Run("should return error if decryption fails with wrong AAD", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
			AAD:      []byte("create-aad"),
		})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
			Secret:   newTestData(t, []byte("data")),
			AAD:      []byte("wrap-aad"),
		})
		assert.NoError(t, err)

		// when
		resp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: tenantID, ID: keyID}},
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("wrong-aad"),
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, keyprocessor.UnwrapSecretResponse{}, resp)
	})

	t.Run("should succeed for processor with internal wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, nil)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
			Secret:   newTestData(t, []byte("payload")),
			AAD:      []byte("aad"),
		})
		assert.NoError(t, err)

		// when
		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: tenantID, ID: keyID}},
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for processor with parent wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parent := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		processor := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, parent)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
			Secret:   newTestData(t, []byte("payload")),
			AAD:      []byte("aad"),
		})
		assert.NoError(t, err)

		// when
		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for processor with internal and parent wrap", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		parent := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}},
		})
		assert.NoError(t, err)

		v := newTestVault(t)
		internal := keyprocessor.NewProcessor("internal", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err = internal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), internal, parent)
		_, err = processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		wrapResp, err := processor.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
			Secret:   newTestData(t, []byte("payload")),
			AAD:      []byte("aad"),
		})
		assert.NoError(t, err)

		// when
		unwrapResp, err := processor.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
			WrappedSecret: wrapResp.WrappedSecret,
			AAD:           []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("payload"), []byte(unwrapResp.Secret.SecureBytes()))
	})
}

func TestDeleteSecret(t *testing.T) {
	t.Run("should not delete if cryptor manages its own decryption key", func(t *testing.T) {
		// given
		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor("", v, newStaticSecretCryptor(t), newTestSecretGen(), nil, nil)

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
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		v.destroyKeyFn = func(ctx context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return nil, errors.New("vault locked")
		}

		// when
		resp, err := processor.DeleteSecret(t.Context(), keyprocessor.DeleteSecretRequest{
			Key: model.Key{TenantID: tenantID, ID: keyID},
		})

		// then
		assert.ErrorContains(t, err, "vault locked")
		assert.Equal(t, keyprocessor.DeleteSecretResponse{}, resp)
	})

	t.Run("should succeed", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()
		parentID := uuid.NewString()

		v := &vaultWrapper{Vault: newTestVault(t)}
		processor := keyprocessor.NewProcessor("", v, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := processor.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: tenantID, ID: parentID}, {TenantID: tenantID, ID: keyID}},
		})
		assert.NoError(t, err)

		v.destroyKeyFn = func(ctx context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
			assert.Equal(t, tenantID, req.TenantID)
			assert.Equal(t, keyID, req.KeyID)
			return v.Vault.DestroyKey(ctx, req)
		}

		// when
		resp, err := processor.DeleteSecret(t.Context(), keyprocessor.DeleteSecretRequest{
			Key: model.Key{TenantID: tenantID, ID: keyID},
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, keyprocessor.DeleteSecretResponse{}, resp)
	})
}

func TestHierarchy(t *testing.T) {
	t.Run("should succeed for two-level chain round trip", func(t *testing.T) {
		// given
		parentV := newTestVault(t)
		parentInternal := keyprocessor.NewProcessor("internal", parentV, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parentInternal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "parent-1"}},
		})
		assert.NoError(t, err)
		parent := keyprocessor.NewProcessor("", parentV, newTestCryptor(), newTestSecretGen(), parentInternal, nil)
		_, err = parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "parent-1"}},
		})
		assert.NoError(t, err)

		child := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, parent)
		_, err = child.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "parent-1"}, {TenantID: "t1", ID: "child-1"}},
		})
		assert.NoError(t, err)

		// when
		wrapResp, err := child.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "parent-1"}, {TenantID: "t1", ID: "child-1"}},
			Secret:   newTestData(t, []byte("classified")),
		})
		assert.NoError(t, err)

		unwrapResp, err := child.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: "t1", ID: "parent-1"}, {TenantID: "t1", ID: "child-1"}},
			WrappedSecret: wrapResp.WrappedSecret,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("classified"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should succeed for three-level chain round trip", func(t *testing.T) {
		// given
		root := keyprocessor.NewProcessor("", newTestVault(t), newStaticSecretCryptor(t), newTestSecretGen(), nil, nil)
		_, err := root.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "root-1"}},
		})
		assert.NoError(t, err)

		midV := newTestVault(t)
		midInternal := keyprocessor.NewProcessor("internal", midV, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err = midInternal.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "mid-1"}},
		})
		assert.NoError(t, err)
		mid := keyprocessor.NewProcessor("", midV, newTestCryptor(), newTestSecretGen(), midInternal, root)
		_, err = mid.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "root-1"}, {TenantID: "t1", ID: "mid-1"}},
		})
		assert.NoError(t, err)

		leaf := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, mid)
		_, err = leaf.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "root-1"}, {TenantID: "t1", ID: "mid-1"}, {TenantID: "t1", ID: "leaf-1"}},
		})
		assert.NoError(t, err)

		// when
		wrapResp, err := leaf.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "root-1"}, {TenantID: "t1", ID: "mid-1"}, {TenantID: "t1", ID: "leaf-1"}},
			Secret:   newTestData(t, []byte("top secret")),
		})
		assert.NoError(t, err)

		unwrapResp, err := leaf.UnwrapSecret(t.Context(), keyprocessor.UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: "t1", ID: "root-1"}, {TenantID: "t1", ID: "mid-1"}, {TenantID: "t1", ID: "leaf-1"}},
			WrappedSecret: wrapResp.WrappedSecret,
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, []byte("top secret"), []byte(unwrapResp.Secret.SecureBytes()))
	})

	t.Run("should return error if parent vault fails during child resolve", func(t *testing.T) {
		// given
		parentVault := &vaultWrapper{Vault: newTestVault(t)}
		parent := keyprocessor.NewProcessor("", parentVault, newTestCryptor(), newTestSecretGen(), nil, nil)
		_, err := parent.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "parent-1"}},
		})
		assert.NoError(t, err)

		child := keyprocessor.NewProcessor("", newTestVault(t), newTestCryptor(), newTestSecretGen(), nil, parent)
		_, err = child.CreateSecret(t.Context(), keyprocessor.CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "parent-1"}, {TenantID: "t1", ID: "child-1"}},
		})
		assert.NoError(t, err)

		parentVault.exportKeyFn = func(context.Context, vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
			return nil, errors.New("parent compromised")
		}

		// when
		resp, err := child.WrapSecret(t.Context(), keyprocessor.WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: "t1", ID: "parent-1"}, {TenantID: "t1", ID: "child-1"}},
			Secret:   newTestData(t, []byte("data")),
		})

		// then
		assert.ErrorContains(t, err, "parent compromised")
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
	generateSecretFn func(context.Context) (*cryptor.GenerateSecretResponse, error)
}

func (w *secretGenWrapper) GenerateSecret(ctx context.Context) (*cryptor.GenerateSecretResponse, error) {
	return w.generateSecretFn(ctx)
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
