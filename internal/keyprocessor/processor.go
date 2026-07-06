package keyprocessor

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/pkg/model"
)

// ErrEmptyKeyChain is returned when an operation receives an empty key chain.
var ErrEmptyKeyChain = errors.New("empty key chain")

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

	genResp, err := p.generator.GenerateSecret(ctx)
	if err != nil {
		return CreateSecretResponse{}, err
	}

	sec, err := p.seal(ctx, key, genResp.Secret, req.AAD)
	if err != nil {
		return CreateSecretResponse{}, err
	}

	sec, err = p.parentWrap(ctx, req.KeyChain, sec, req.AAD)
	if err != nil {
		return CreateSecretResponse{}, err
	}

	_, err = p.vault.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    key.TenantID,
		KeyID:       key.ID,
		KeyVersion:  1,
		KeyMaterial: sec,
		AAD:         req.AAD,
	})
	return CreateSecretResponse{}, errors.Join(err, destroySec(sec))
}

// WrapSecret resolves the wrapping secret from the key chain and encrypts the given secret.
// When the wrapper manages its own decryption key, it encrypts directly without resolving.
func (p *Processor) WrapSecret(ctx context.Context, req WrapSecretRequest) (WrapSecretResponse, error) {
	sec, err := p.resolveSecret(ctx, req.KeyChain)
	if err != nil {
		return WrapSecretResponse{}, err
	}

	key, err := lastKey(req.KeyChain)
	if err != nil {
		return WrapSecretResponse{}, errors.Join(err, destroySec(sec))
	}

	encResp, err := p.wrapper.Encrypt(ctx, cryptor.EncryptRequest{
		TenantID:   key.TenantID,
		KeyID:      key.ID,
		KeyVersion: 1,
		Secret:     toCryptorSecret(sec),
		Plaintext:  req.Secret,
		AAD:        req.AAD,
	})
	if err := errors.Join(err, destroySec(sec)); err != nil {
		if encResp != nil {
			return WrapSecretResponse{}, errors.Join(err, destroySec(encResp.Ciphertext))
		}
		return WrapSecretResponse{}, err
	}

	return WrapSecretResponse{
		WrappedSecret: encResp.Ciphertext,
	}, nil
}

// UnwrapSecret resolves the wrapping secret from the key chain and decrypts the given wrapped secret.
// When the wrapper manages its own decryption key, it decrypts directly without resolving.
func (p *Processor) UnwrapSecret(ctx context.Context, req UnwrapSecretRequest) (UnwrapSecretResponse, error) {
	sec, err := p.resolveSecret(ctx, req.KeyChain)
	if err != nil {
		return UnwrapSecretResponse{}, err
	}

	key, err := lastKey(req.KeyChain)
	if err != nil {
		return UnwrapSecretResponse{}, errors.Join(err, destroySec(sec))
	}

	decResp, err := p.wrapper.Decrypt(ctx, cryptor.DecryptRequest{
		TenantID:   key.TenantID,
		KeyID:      key.ID,
		KeyVersion: 1,
		Secret:     toCryptorSecret(sec),
		Ciphertext: req.WrappedSecret,
		AAD:        req.AAD,
	})
	if err := errors.Join(err, destroySec(sec)); err != nil {
		if decResp != nil {
			return UnwrapSecretResponse{}, errors.Join(err, destroySec(decResp.Plaintext))
		}
		return UnwrapSecretResponse{}, err
	}

	return UnwrapSecretResponse{
		Secret: decResp.Plaintext,
	}, nil
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

	exported, err := p.vault.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID: key.TenantID,
		KeyID:    key.ID,
	})
	if err != nil {
		return nil, err
	}

	sec, err := p.parentUnwrap(ctx, keyChain, exported.KeyMaterial, exported.AAD)
	if err != nil {
		return nil, err
	}

	return p.unseal(ctx, key, sec, exported.AAD)
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
	if err := errors.Join(err, destroySec(sec)); err != nil {
		if resp.Ciphertext != nil {
			return nil, errors.Join(err, destroySec(resp.Ciphertext))
		}
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
	if err := errors.Join(err, destroySec(sec)); err != nil {
		if resp.Plaintext != nil {
			return nil, errors.Join(err, destroySec(resp.Plaintext))
		}
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
	if err := errors.Join(err, destroySec(sec)); err != nil {
		return nil, errors.Join(err, destroySec(resp.WrappedSecret))
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
	if err := errors.Join(err, destroySec(sec)); err != nil {
		return nil, errors.Join(err, destroySec(resp.Secret))
	}
	return resp.Secret, nil
}

func lastKey(keyChain []model.Key) (model.Key, error) {
	if len(keyChain) == 0 {
		return model.Key{}, ErrEmptyKeyChain
	}
	return keyChain[len(keyChain)-1], nil
}

func destroySec(sec *securemem.Data) error {
	if sec != nil {
		return sec.Destroy()
	}
	return nil
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
