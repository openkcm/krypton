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
	name            string
	vault           vault.Vault
	cryptor         cryptor.Cryptor
	secretGenerator cryptor.SecretGenerator
	internal        *Processor
	parent          *Processor
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

// CreateSecret generates a secret, wraps it through the internal and parent chain, and stores it in the vault.
// It is a no-op when the cryptor manages its own decryption key regardless of internal or parent configuration.
func (p *Processor) CreateSecret(ctx context.Context, req CreateSecretRequest) (CreateSecretResponse, error) {
	if !p.cryptor.Info().DecryptionSecretRequired {
		return CreateSecretResponse{}, nil
	}

	key, err := lastKey(req.KeyChain)
	if err != nil {
		return CreateSecretResponse{}, err
	}

	genResp, err := p.secretGenerator.GenerateSecret(ctx)
	if err != nil {
		return CreateSecretResponse{}, err
	}

	sec := genResp.Secret

	if p.internal != nil {
		_, err := p.internal.CreateSecret(ctx, CreateSecretRequest{
			KeyChain: []model.Key{{TenantID: key.TenantID, ID: key.ID}},
			AAD:      req.AAD,
		})
		if err != nil {
			return CreateSecretResponse{}, errors.Join(err, destroyAll(genResp.Secret))
		}

		resp, err := p.internal.WrapSecret(ctx, WrapSecretRequest{
			KeyChain: []model.Key{{TenantID: key.TenantID, ID: key.ID}},
			Secret:   sec,
			AAD:      req.AAD,
		})
		if err != nil {
			return CreateSecretResponse{}, errors.Join(err, destroyAll(genResp.Secret))
		}
		if err := destroyAll(sec); err != nil {
			return CreateSecretResponse{}, err
		}
		sec = resp.WrappedSecret
	}

	if p.parent != nil {
		resp, err := p.parent.WrapSecret(ctx, WrapSecretRequest{
			KeyChain: req.KeyChain[:len(req.KeyChain)-1],
			Secret:   sec,
			AAD:      req.AAD,
		})
		if err != nil {
			return CreateSecretResponse{}, errors.Join(err, destroyAll(genResp.Secret, sec))
		}
		if err := destroyAll(sec); err != nil {
			return CreateSecretResponse{}, err
		}
		sec = resp.WrappedSecret
	}

	_, err = p.vault.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    key.TenantID,
		KeyID:       p.keyID(key.ID),
		KeyVersion:  1,
		KeyMaterial: sec,
		AAD:         req.AAD,
	})
	if err != nil {
		return CreateSecretResponse{}, errors.Join(err, destroyAll(genResp.Secret, sec))
	}

	if err := destroyAll(genResp.Secret, sec); err != nil {
		return CreateSecretResponse{}, err
	}
	return CreateSecretResponse{}, nil
}

// WrapSecret resolves the processor's secret from the vault and uses it to encrypt the given plaintext.
// When the cryptor manages its own decryption key, it encrypts directly without resolving.
func (p *Processor) WrapSecret(ctx context.Context, req WrapSecretRequest) (WrapSecretResponse, error) {
	sec, err := p.resolveSecret(ctx, req.KeyChain)
	if err != nil {
		return WrapSecretResponse{}, err
	}

	key, err := lastKey(req.KeyChain)
	if err != nil {
		return WrapSecretResponse{}, errors.Join(err, destroyAll(sec))
	}

	encResp, err := p.cryptor.Encrypt(ctx, cryptor.EncryptRequest{
		TenantID:   key.TenantID,
		KeyID:      p.keyID(key.ID),
		KeyVersion: 1,
		Secret:     toCryptorSecret(sec),
		Plaintext:  req.Secret,
		AAD:        req.AAD,
	})
	if err != nil {
		return WrapSecretResponse{}, errors.Join(err, destroyAll(sec))
	}

	if err := destroyAll(sec); err != nil {
		return WrapSecretResponse{}, err
	}
	return WrapSecretResponse{
		WrappedSecret: encResp.Ciphertext,
	}, nil
}

// UnwrapSecret resolves the processor's secret from the vault and uses it to decrypt the given ciphertext.
// When the cryptor manages its own decryption key, it decrypts directly without resolving.
func (p *Processor) UnwrapSecret(ctx context.Context, req UnwrapSecretRequest) (UnwrapSecretResponse, error) {
	sec, err := p.resolveSecret(ctx, req.KeyChain)
	if err != nil {
		return UnwrapSecretResponse{}, err
	}

	key, err := lastKey(req.KeyChain)
	if err != nil {
		return UnwrapSecretResponse{}, errors.Join(err, destroyAll(sec))
	}

	decResp, err := p.cryptor.Decrypt(ctx, cryptor.DecryptRequest{
		TenantID:   key.TenantID,
		KeyID:      p.keyID(key.ID),
		KeyVersion: 1,
		Secret:     toCryptorSecret(sec),
		Ciphertext: req.WrappedSecret,
		AAD:        req.AAD,
	})
	if err != nil {
		return UnwrapSecretResponse{}, errors.Join(err, destroyAll(sec))
	}

	if err := destroyAll(sec); err != nil {
		return UnwrapSecretResponse{}, err
	}
	return UnwrapSecretResponse{
		Secret: decResp.Plaintext,
	}, nil
}

// DeleteSecret removes the processor's secret and its internal processor's secret from the vault.
// It is a no-op when the cryptor manages its own decryption key regardless of internal or parent configuration.
func (p *Processor) DeleteSecret(ctx context.Context, req DeleteSecretRequest) (DeleteSecretResponse, error) {
	if !p.cryptor.Info().DecryptionSecretRequired {
		return DeleteSecretResponse{}, nil
	}

	_, err := p.vault.DestroyKey(ctx, vault.DestroyKeyRequest{
		TenantID: req.Key.TenantID,
		KeyID:    p.keyID(req.Key.ID),
	})
	if err != nil {
		return DeleteSecretResponse{}, err
	}

	if p.internal != nil {
		_, err = p.internal.DeleteSecret(ctx, DeleteSecretRequest{
			Key: model.Key{TenantID: req.Key.TenantID, ID: req.Key.ID},
		})
		if err != nil {
			return DeleteSecretResponse{}, err
		}
	}

	return DeleteSecretResponse{}, nil
}

func (p *Processor) resolveSecret(ctx context.Context, keyChain []model.Key) (*securemem.Data, error) {
	if !p.cryptor.Info().DecryptionSecretRequired {
		return nil, nil //nolint:nilnil
	}

	key, err := lastKey(keyChain)
	if err != nil {
		return nil, err
	}

	exported, err := p.vault.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID: key.TenantID,
		KeyID:    p.keyID(key.ID),
	})
	if err != nil {
		return nil, err
	}

	sec := exported.KeyMaterial
	aad := exported.AAD

	if p.parent != nil {
		resp, err := p.parent.UnwrapSecret(ctx, UnwrapSecretRequest{
			KeyChain:      keyChain[:len(keyChain)-1],
			WrappedSecret: sec,
			AAD:           aad,
		})
		if err != nil {
			return nil, errors.Join(err, destroyAll(sec))
		}
		if err := destroyAll(sec); err != nil {
			return nil, err
		}
		sec = resp.Secret
	}

	if p.internal != nil {
		resp, err := p.internal.UnwrapSecret(ctx, UnwrapSecretRequest{
			KeyChain:      []model.Key{{TenantID: key.TenantID, ID: key.ID}},
			WrappedSecret: sec,
			AAD:           aad,
		})
		if err != nil {
			return nil, errors.Join(err, destroyAll(sec))
		}
		if err := destroyAll(sec); err != nil {
			return nil, err
		}
		sec = resp.Secret
	}

	return sec, nil
}

func (p *Processor) keyID(id string) string {
	if p.name == "" {
		return id
	}
	return p.name + "/" + id
}

func lastKey(keyChain []model.Key) (model.Key, error) {
	if len(keyChain) == 0 {
		return model.Key{}, ErrEmptyKeyChain
	}
	return keyChain[len(keyChain)-1], nil
}

func destroyAll(secrets ...*securemem.Data) error {
	var errs []error
	for _, s := range secrets {
		if s != nil {
			if err := s.Destroy(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
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
