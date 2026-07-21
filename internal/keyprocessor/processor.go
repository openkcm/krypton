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
	// ErrMissingParentKeyVersion is returned when a processor has a parent cryptor set
	// but the key version does not specify a parent key ID or parent key version.
	ErrMissingParentKeyVersion = errors.New("parent set but key version has no parent key version")
	// ErrSecNotPersisted is returned when a handler completes successfully
	// but the secret is missing from the persistent vault, indicating a bug
	ErrSecNotPersisted = errors.New("persisted secret missing from handler response")
)

// processor creates, wraps, unwraps, and deletes secrets within a key hierarchy.
// It destroys all intermediate secrets that pass through its operations.
type processor struct {
	generator       cryptor.SecretGenerator
	cryptor         cryptor.Cryptor
	transportSealer cryptor.Sealer
	parent          SecretWrapper
	vault           vault.Vault
}

// createSecretRequest is the input for CreateSecret.
type createSecretRequest struct {
	KeyVersion model.KeyVersion
	AAD        []byte
}

// createSecretResponse is the output of CreateSecret.
type createSecretResponse struct{}

// wrapSecretRequest is the input for WrapSecret.
type wrapSecretRequest struct {
	KeyVersion model.KeyVersion
	Secret     *securemem.Data
	AAD        []byte
}

// wrapSecretResponse is the output of WrapSecret.
type wrapSecretResponse struct {
	WrappedSecret *securemem.Data
}

// unwrapSecretRequest is the input for UnwrapSecret.
type unwrapSecretRequest struct {
	KeyVersion    model.KeyVersion
	WrappedSecret *securemem.Data
	AAD           []byte
}

// unwrapSecretResponse is the output of UnwrapSecret.
type unwrapSecretResponse struct {
	Secret *securemem.Data
}

// deleteSecretRequest is the input for DeleteSecret.
type deleteSecretRequest struct {
	KeyVersion model.KeyVersion
}

// deleteSecretResponse is the output of DeleteSecret.
type deleteSecretResponse struct{}

// createSecret generates a secret, seals it, wraps it through the parent chain, and stores it in the vault.
// It is a no-op when the cryptor manages its own decryption key.
func (p *processor) createSecret(ctx context.Context, req createSecretRequest) (createSecretResponse, error) {
	if !p.cryptor.Info().DecryptionSecretRequired {
		return createSecretResponse{}, nil
	}

	_, err := securemem.Run(ctx, func(ctx context.Context, _ *securemem.HandlerRequest) error {
		resp, err := p.generator.GenerateSecret(ctx)
		if err != nil {
			return err
		}
		defer destroySec(resp.Secret)

		sealSec, err := p.transportSeal(ctx, resp.Secret, req.AAD)
		if err != nil {
			return err
		}
		defer destroySec(sealSec)

		wrapSec, err := p.parentWrap(ctx, req.KeyVersion, sealSec, req.AAD)
		if err != nil {
			return err
		}
		defer destroySec(wrapSec)

		_, err = p.vault.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    req.KeyVersion.TenantID,
			KeyID:       req.KeyVersion.KeyID,
			KeyVersion:  req.KeyVersion.Version,
			KeyRevision: req.KeyVersion.Revision,
			KeyMaterial: wrapSec,
			AAD:         req.AAD,
		})
		return err
	})

	return createSecretResponse{}, err
}

// wrapSecret resolves the wrapping secret from the key chain and encrypts the given secret.
// When the cryptor manages its own decryption key, it encrypts directly without resolving.
func (p *processor) wrapSecret(ctx context.Context, req wrapSecretRequest) (wrapSecretResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		sec, err := p.resolveSecret(ctx, req.KeyVersion)
		if err != nil {
			return err
		}
		defer destroySec(sec)

		encResp, err := p.cryptor.Encrypt(ctx, cryptor.EncryptRequest{
			Secret:    toCryptorSecret(sec),
			Plaintext: req.Secret,
			AAD:       req.AAD,
		})
		if err != nil {
			return err
		}

		return sreq.PersistentVault().Import(persistSecName, encResp.Ciphertext)
	})
	if err != nil {
		return wrapSecretResponse{}, err
	}
	sec, err := getPersistedSec(resp)

	return wrapSecretResponse{
		WrappedSecret: sec,
	}, err
}

// unwrapSecret resolves the wrapping secret from the key chain and decrypts the given wrapped secret.
// When the cryptor manages its own decryption key, it decrypts directly without resolving.
func (p *processor) unwrapSecret(ctx context.Context, req unwrapSecretRequest) (unwrapSecretResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		sec, err := p.resolveSecret(ctx, req.KeyVersion)
		if err != nil {
			return err
		}
		defer destroySec(sec)

		decResp, err := p.cryptor.Decrypt(ctx, cryptor.DecryptRequest{
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
		return unwrapSecretResponse{}, err
	}
	sec, err := getPersistedSec(resp)

	return unwrapSecretResponse{
		Secret: sec,
	}, err
}

// deleteSecret removes the wrapping secret from the vault.
// It is a no-op when the cryptor manages its own decryption key.
func (p *processor) deleteSecret(ctx context.Context, req deleteSecretRequest) (deleteSecretResponse, error) {
	if !p.cryptor.Info().DecryptionSecretRequired {
		return deleteSecretResponse{}, nil
	}

	_, err := p.vault.DestroyKey(ctx, vault.DestroyKeyRequest{
		TenantID:    req.KeyVersion.TenantID,
		KeyID:       req.KeyVersion.KeyID,
		KeyVersion:  req.KeyVersion.Version,
		KeyRevision: req.KeyVersion.Revision,
	})
	if err != nil {
		return deleteSecretResponse{}, err
	}

	return deleteSecretResponse{}, nil
}

func (p *processor) resolveSecret(ctx context.Context, kv model.KeyVersion) (*securemem.Data, error) {
	if !p.cryptor.Info().DecryptionSecretRequired {
		return nil, nil //nolint:nilnil
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		exported, err := p.vault.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:    kv.TenantID,
			KeyID:       kv.KeyID,
			KeyVersion:  kv.Version,
			KeyRevision: kv.Revision,
		})
		if err != nil {
			return err
		}
		defer destroySec(exported.KeyMaterial)

		unwrapSec, err := p.parentUnwrap(ctx, kv, exported.KeyMaterial, exported.AAD)
		if err != nil {
			return err
		}
		defer destroySec(unwrapSec)

		unsealSec, err := p.unseal(ctx, unwrapSec, exported.AAD)
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

func (p *processor) transportSeal(ctx context.Context, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.transportSealer == nil {
		return sec, nil
	}
	resp, err := p.transportSealer.Seal(ctx, cryptor.SealRequest{
		Plaintext: sec,
		AAD:       aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (p *processor) unseal(ctx context.Context, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.transportSealer == nil {
		return sec, nil
	}
	resp, err := p.transportSealer.Unseal(ctx, cryptor.UnsealRequest{
		Ciphertext: sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (p *processor) parentWrap(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.parent == nil {
		return sec, nil
	}
	if kv.ParentKeyID == nil || kv.ParentKeyVersion == nil {
		return nil, ErrMissingParentKeyVersion
	}
	resp, err := p.parent.WrapSecret(ctx, WrapSecretRequest{
		TenantID:   kv.TenantID,
		KeyID:      *kv.ParentKeyID,
		KeyVersion: *kv.ParentKeyVersion,
		Secret:     sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.WrappedSecret, nil
}

func (p *processor) parentUnwrap(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.parent == nil {
		return sec, nil
	}
	if kv.ParentKeyID == nil || kv.ParentKeyVersion == nil {
		return nil, ErrMissingParentKeyVersion
	}
	resp, err := p.parent.UnwrapSecret(ctx, UnwrapSecretRequest{
		TenantID:      kv.TenantID,
		KeyID:         *kv.ParentKeyID,
		KeyVersion:    *kv.ParentKeyVersion,
		WrappedSecret: sec,
		AAD:           aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Secret, nil
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
