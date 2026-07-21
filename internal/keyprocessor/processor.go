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

// Processor creates, wraps, unwraps, and deletes secrets within a key hierarchy.
// It destroys all intermediate secrets that pass through its operations.
type Processor struct {
	generator       cryptor.SecretGenerator
	wrapper         cryptor.Cryptor
	transportSealer cryptor.Cryptor
	parent          cryptor.Cryptor
	vault           vault.Vault
}

// CreateSecretRequest is the input for CreateSecret.
type CreateSecretRequest struct {
	KeyVersion model.KeyVersion
	AAD        []byte
}

// CreateSecretResponse is the output of CreateSecret.
type CreateSecretResponse struct{}

// WrapSecretRequest is the input for WrapSecret.
type WrapSecretRequest struct {
	KeyVersion model.KeyVersion
	Secret     *securemem.Data
	AAD        []byte
}

// WrapSecretResponse is the output of WrapSecret.
type WrapSecretResponse struct {
	WrappedSecret *securemem.Data
}

// UnwrapSecretRequest is the input for UnwrapSecret.
type UnwrapSecretRequest struct {
	KeyVersion    model.KeyVersion
	WrappedSecret *securemem.Data
	AAD           []byte
}

// UnwrapSecretResponse is the output of UnwrapSecret.
type UnwrapSecretResponse struct {
	Secret *securemem.Data
}

// DeleteSecretRequest is the input for DeleteSecret.
type DeleteSecretRequest struct {
	KeyVersion model.KeyVersion
}

// DeleteSecretResponse is the output of DeleteSecret.
type DeleteSecretResponse struct{}

// CreateSecret generates a secret, seals it, wraps it through the parent chain, and stores it in the vault.
// It is a no-op when the wrapper manages its own decryption key.
func (p *Processor) CreateSecret(ctx context.Context, req CreateSecretRequest) (CreateSecretResponse, error) {
	if !p.wrapper.Info().DecryptionSecretRequired {
		return CreateSecretResponse{}, nil
	}

	_, err := securemem.Run(ctx, func(ctx context.Context, _ *securemem.HandlerRequest) error {
		resp, err := p.generator.GenerateSecret(ctx)
		if err != nil {
			return err
		}
		defer destroySec(resp.Secret)

		sealSec, err := p.transportSeal(ctx, req.KeyVersion, resp.Secret, req.AAD)
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

	return CreateSecretResponse{}, err
}

// WrapSecret resolves the wrapping secret from the key chain and encrypts the given secret.
// When the wrapper manages its own decryption key, it encrypts directly without resolving.
func (p *Processor) WrapSecret(ctx context.Context, req WrapSecretRequest) (WrapSecretResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		sec, err := p.resolveSecret(ctx, req.KeyVersion)
		if err != nil {
			return err
		}
		defer destroySec(sec)

		encResp, err := p.wrapper.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   req.KeyVersion.TenantID,
			KeyID:      req.KeyVersion.KeyID,
			KeyVersion: req.KeyVersion.Version,
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
		sec, err := p.resolveSecret(ctx, req.KeyVersion)
		if err != nil {
			return err
		}
		defer destroySec(sec)

		decResp, err := p.wrapper.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   req.KeyVersion.TenantID,
			KeyID:      req.KeyVersion.KeyID,
			KeyVersion: req.KeyVersion.Version,
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
		TenantID:    req.KeyVersion.TenantID,
		KeyID:       req.KeyVersion.KeyID,
		KeyVersion:  req.KeyVersion.Version,
		KeyRevision: req.KeyVersion.Revision,
	})
	if err != nil {
		return DeleteSecretResponse{}, err
	}

	return DeleteSecretResponse{}, nil
}

func (p *Processor) resolveSecret(ctx context.Context, kv model.KeyVersion) (*securemem.Data, error) {
	if !p.wrapper.Info().DecryptionSecretRequired {
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

		unsealSec, err := p.unseal(ctx, kv, unwrapSec, exported.AAD)
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

func (p *Processor) transportSeal(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.transportSealer == nil {
		return sec, nil
	}
	resp, err := p.transportSealer.Encrypt(ctx, cryptor.EncryptRequest{
		TenantID:   kv.TenantID,
		KeyID:      kv.KeyID,
		KeyVersion: kv.Version,
		Plaintext:  sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (p *Processor) unseal(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.transportSealer == nil {
		return sec, nil
	}
	resp, err := p.transportSealer.Decrypt(ctx, cryptor.DecryptRequest{
		TenantID:   kv.TenantID,
		KeyID:      kv.KeyID,
		KeyVersion: kv.Version,
		Ciphertext: sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (p *Processor) parentWrap(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.parent == nil {
		return sec, nil
	}
	if kv.ParentKeyID == nil || kv.ParentKeyVersion == nil {
		return nil, ErrMissingParentKeyVersion
	}
	resp, err := p.parent.Encrypt(ctx, cryptor.EncryptRequest{
		TenantID:   kv.TenantID,
		KeyID:      *kv.ParentKeyID,
		KeyVersion: *kv.ParentKeyVersion,
		Plaintext:  sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (p *Processor) parentUnwrap(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.parent == nil {
		return sec, nil
	}
	if kv.ParentKeyID == nil || kv.ParentKeyVersion == nil {
		return nil, ErrMissingParentKeyVersion
	}
	resp, err := p.parent.Decrypt(ctx, cryptor.DecryptRequest{
		TenantID:   kv.TenantID,
		KeyID:      *kv.ParentKeyID,
		KeyVersion: *kv.ParentKeyVersion,
		Ciphertext: sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
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
