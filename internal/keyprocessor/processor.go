package keyprocessor

import (
	"context"
	"errors"
	"log/slog"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/pkg/model"
)

const persistSecName = "persistedSec"

var (
	// ErrEmptyKeyChain is returned when an operation receives an empty key chain.
	ErrEmptyKeyChain = errors.New("empty key chain")
	// ErrSecNotPersisted is returned when a handler completes successfully
	// but the secret is missing from the persistent vault, indicating a bug
	ErrSecNotPersisted = errors.New("persisted secret missing from handler response")
)

// Processor creates, wraps, unwraps, and deletes secrets within a key hierarchy.
// It destroys all intermediate secrets that pass through its operations.
type Processor struct {
	generator cryptor.SecretGenerator
	wrapper   cryptor.Cryptor
	sealer    cryptor.Cryptor
	vault     vault.Vault
	parent    *Processor
}

// CreateSecretRequest is the input for CreateSecret.
type CreateSecretRequest struct {
	KeyChain []model.Key
	AAD      []byte
}

// CreateSecretResponse is the output of CreateSecret.
type CreateSecretResponse struct{}

// WrapSecretRequest is the input for WrapSecret.
type WrapSecretRequest struct {
	KeyChain []model.Key
	Secret   *securemem.Data
	AAD      []byte
}

// WrapSecretResponse is the output of WrapSecret.
type WrapSecretResponse struct {
	WrappedSecret *securemem.Data
}

// UnwrapSecretRequest is the input for UnwrapSecret.
type UnwrapSecretRequest struct {
	KeyChain      []model.Key
	WrappedSecret *securemem.Data
	AAD           []byte
}

// UnwrapSecretResponse is the output of UnwrapSecret.
type UnwrapSecretResponse struct {
	Secret *securemem.Data
}

// DeleteSecretRequest is the input for DeleteSecret.
type DeleteSecretRequest struct {
	Key model.Key
}

// DeleteSecretResponse is the output of DeleteSecret.
type DeleteSecretResponse struct{}

// CreateSecret generates a secret, seals it, wraps it through the parent chain, and stores it in the vault.
// It is a no-op when the wrapper manages its own decryption key.
func (p *Processor) CreateSecret(ctx context.Context, req CreateSecretRequest) (CreateSecretResponse, error) {
	if !p.wrapper.Info().DecryptionSecretRequired {
		return CreateSecretResponse{}, nil
	}

	key, err := lastKey(req.KeyChain)
	if err != nil {
		return CreateSecretResponse{}, err
	}

	_, err = securemem.Run(ctx, func(ctx context.Context, _ *securemem.HandlerRequest) error {
		resp, err := p.generator.GenerateSecret(ctx)
		if err != nil {
			return err
		}
		defer destroySec(resp.Secret)

		sealSec, err := p.seal(ctx, key, resp.Secret, req.AAD)
		if err != nil {
			return err
		}
		defer destroySec(sealSec)

		wrapSec, err := p.parentWrap(ctx, req.KeyChain, sealSec, req.AAD)
		if err != nil {
			return err
		}
		defer destroySec(wrapSec)

		_, err = p.vault.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    key.TenantID,
			KeyID:       key.ID,
			KeyVersion:  1,
			KeyMaterial: wrapSec,
			AAD:         req.AAD,
		})
		return err
	})

	return CreateSecretResponse{}, err
}

// WrapSecret resolves the wrapping secret from the key chain and encrypts the given secret.
// When the wrapper manages its own decryption key, it encrypts directly without resolving.
func (p *Processor) WrapSecret(ctx context.Context, req WrapSecretRequest) (WrapSecretResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		sec, err := p.resolveSecret(ctx, req.KeyChain)
		if err != nil {
			return err
		}
		defer destroySec(sec)

		key, err := lastKey(req.KeyChain)
		if err != nil {
			return err
		}

		encResp, err := p.wrapper.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Secret:     toCryptorSecret(sec),
			Plaintext:  req.Secret,
			AAD:        req.AAD,
		})
		if err != nil {
			return err
		}

		return sreq.PersistentVault().Import(persistSecName, encResp.Ciphertext)
	})
	if err != nil {
		return WrapSecretResponse{}, err
	}
	sec, err := getPersistedSec(resp)

	return WrapSecretResponse{
		WrappedSecret: sec,
	}, err
}

// UnwrapSecret resolves the wrapping secret from the key chain and decrypts the given wrapped secret.
// When the wrapper manages its own decryption key, it decrypts directly without resolving.
func (p *Processor) UnwrapSecret(ctx context.Context, req UnwrapSecretRequest) (UnwrapSecretResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		sec, err := p.resolveSecret(ctx, req.KeyChain)
		if err != nil {
			return err
		}
		defer destroySec(sec)

		key, err := lastKey(req.KeyChain)
		if err != nil {
			return err
		}

		decResp, err := p.wrapper.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   key.TenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Secret:     toCryptorSecret(sec),
			Ciphertext: req.WrappedSecret,
			AAD:        req.AAD,
		})
		if err != nil {
			return err
		}

		return sreq.PersistentVault().Import(persistSecName, decResp.Plaintext)
	})
	if err != nil {
		return UnwrapSecretResponse{}, err
	}
	sec, err := getPersistedSec(resp)

	return UnwrapSecretResponse{
		Secret: sec,
	}, err
}

// DeleteSecret removes the wrapping secret from the vault.
// It is a no-op when the wrapper manages its own decryption key.
func (p *Processor) DeleteSecret(ctx context.Context, req DeleteSecretRequest) (DeleteSecretResponse, error) {
	if !p.wrapper.Info().DecryptionSecretRequired {
		return DeleteSecretResponse{}, nil
	}

	_, err := p.vault.DestroyKey(ctx, vault.DestroyKeyRequest{
		TenantID: req.Key.TenantID,
		KeyID:    req.Key.ID,
	})
	if err != nil {
		return DeleteSecretResponse{}, err
	}

	return DeleteSecretResponse{}, nil
}

func (p *Processor) resolveSecret(ctx context.Context, keyChain []model.Key) (*securemem.Data, error) {
	if !p.wrapper.Info().DecryptionSecretRequired {
		return nil, nil //nolint:nilnil
	}

	key, err := lastKey(keyChain)
	if err != nil {
		return nil, err
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		exported, err := p.vault.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID: key.TenantID,
			KeyID:    key.ID,
		})
		if err != nil {
			return err
		}
		defer destroySec(exported.KeyMaterial)

		unwrapSec, err := p.parentUnwrap(ctx, keyChain, exported.KeyMaterial, exported.AAD)
		if err != nil {
			return err
		}
		defer destroySec(unwrapSec)

		unsealSec, err := p.unseal(ctx, key, unwrapSec, exported.AAD)
		if err != nil {
			return err
		}
		defer destroySec(unsealSec)

		// copy so that defers can unconditionally destroy all intermediates.
		sec, err := copySec(unsealSec)
		if err != nil {
			return nil
		}

		return sreq.PersistentVault().Import(persistSecName, sec)
	})
	if err != nil {
		return nil, err
	}

	return getPersistedSec(resp)
}

func (p *Processor) seal(ctx context.Context, key model.Key, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.sealer == nil {
		return sec, nil
	}
	resp, err := p.sealer.Encrypt(ctx, cryptor.EncryptRequest{
		TenantID:   key.TenantID,
		KeyID:      key.ID,
		KeyVersion: 1,
		Plaintext:  sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (p *Processor) unseal(ctx context.Context, key model.Key, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.sealer == nil {
		return sec, nil
	}
	resp, err := p.sealer.Decrypt(ctx, cryptor.DecryptRequest{
		TenantID:   key.TenantID,
		KeyID:      key.ID,
		KeyVersion: 1,
		Ciphertext: sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (p *Processor) parentWrap(ctx context.Context, keyChain []model.Key, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.parent == nil {
		return sec, nil
	}
	resp, err := p.parent.WrapSecret(ctx, WrapSecretRequest{
		KeyChain: keyChain[:len(keyChain)-1],
		Secret:   sec,
		AAD:      aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.WrappedSecret, nil
}

func (p *Processor) parentUnwrap(ctx context.Context, keyChain []model.Key, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.parent == nil {
		return sec, nil
	}
	resp, err := p.parent.UnwrapSecret(ctx, UnwrapSecretRequest{
		KeyChain:      keyChain[:len(keyChain)-1],
		WrappedSecret: sec,
		AAD:           aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Secret, nil
}

func lastKey(keyChain []model.Key) (model.Key, error) {
	if len(keyChain) == 0 {
		return model.Key{}, ErrEmptyKeyChain
	}
	return keyChain[len(keyChain)-1], nil
}

func destroySec(sec *securemem.Data) {
	if sec == nil {
		return
	}
	if err := sec.Destroy(); err != nil {
		slog.Error("failed to destroy secret", "name", sec.Name(), "error", err)
	}
}

func getPersistedSec(resp *securemem.HandlerResponse) (*securemem.Data, error) {
	sec, ok := resp.MemVault().Get(persistSecName)
	if !ok {
		err := resp.MemVault().DestroyAll()
		return nil, errors.Join(ErrSecNotPersisted, err)
	}
	return sec, nil
}

func copySec(src *securemem.Data) (*securemem.Data, error) {
	dst, err := securemem.NewData(src.Name(), len(src.SecureBytes()))
	if err != nil {
		return nil, err
	}
	copy(dst.SecureBytes(), src.SecureBytes())
	return dst, nil
}

func toCryptorSecret(data *securemem.Data) *cryptor.Secret {
	if data == nil {
		return nil
	}
	return &cryptor.Secret{
		Algorithm: cryptor.KeyAlgorithmAES256,
		Data:      data,
	}
}
