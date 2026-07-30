package keyprocessor

import (
	"context"
	"errors"
	"log/slog"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/model"
)

const persistSecName = "persistedSec"

var (
	// ErrMissingParentKey is returned when a processor has a parent set
	// but the key version does not specify a parent key ID.
	ErrMissingParentKey = errors.New("parent set but key version has no parent key")
	// ErrSecNotPersisted is returned when a handler completes successfully
	// but the secret is missing from the persistent vault, indicating a bug
	ErrSecNotPersisted = errors.New("persisted secret missing from handler response")
)

// processor manages secret lifecycle and encryption within a key hierarchy.
type processor struct {
	generator       cryptor.SecretGenerator
	cryptor         cryptor.Cryptor
	transportSealer cryptor.Sealer
	parent          cryptor.Sealer
	vault           vault.Vault
}

// newProcessor builds a processor from a key binding and its parent sealer.
// It resolves the optional cryptor bundle, vault, and transport sealer from
// the binding's provider specs.
func newProcessor(ctx context.Context, binding spec.KeyBinding, parent cryptor.Sealer) (*processor, error) {
	p := &processor{parent: parent}

	if binding.CryptorSpec != nil {
		bundle, err := cryptorprovider.GetBundle(ctx, *binding.CryptorSpec)
		if err != nil {
			return nil, err
		}
		p.cryptor = bundle.Cryptor
		p.generator = bundle.SecretGenerator
	}

	if binding.VaultSpec != nil {
		v, err := vaultprovider.GetVault(ctx, *binding.VaultSpec)
		if err != nil {
			return nil, err
		}
		p.vault = v
	}

	if binding.SealerSpec != nil {
		sealer, err := sealerprovider.GetSealer(ctx, *binding.SealerSpec)
		if err != nil {
			return nil, err
		}
		p.transportSealer = sealer
	}

	return p, nil
}

type createSecretRequest struct {
	KeyVersion model.KeyVersion
	AAD        []byte
}

type createSecretResponse struct{}

type deleteSecretRequest struct {
	KeyVersion model.KeyVersion
}

type deleteSecretResponse struct{}

// createSecret generates, seals, and stores a new secret for the given key version.
func (p *processor) createSecret(ctx context.Context, req createSecretRequest) (createSecretResponse, error) {
	_, err := securemem.Run(ctx, func(ctx context.Context, _ *securemem.HandlerRequest) error {
		resp, err := p.generator.GenerateSecret(ctx)
		if err != nil {
			return err
		}
		defer destroySec(resp.Secret)

		transSealed, err := p.transportSeal(ctx, req.KeyVersion, resp.Secret, req.AAD)
		if err != nil {
			return err
		}
		defer destroySec(transSealed)

		parentSealed, err := p.parentSeal(ctx, req.KeyVersion, transSealed, req.AAD)
		if err != nil {
			return err
		}
		defer destroySec(parentSealed)

		_, err = p.vault.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    req.KeyVersion.TenantID,
			KeyID:       req.KeyVersion.KeyID,
			KeyVersion:  req.KeyVersion.Version,
			KeyRevision: req.KeyVersion.Revision,
			KeyMaterial: parentSealed,
			AAD:         req.AAD,
		})
		return err
	})

	return createSecretResponse{}, err
}

// encrypt encrypts plaintext using the provided secret.
func (p *processor) encrypt(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		encResp, err := p.cryptor.Encrypt(ctx, req)
		if err != nil {
			return err
		}

		return sreq.PersistentVault().Import(persistSecName, encResp.Ciphertext)
	})
	if err != nil {
		return nil, err
	}
	sec, err := getPersistedSec(resp)
	if err != nil {
		return nil, err
	}

	return &cryptor.EncryptResponse{
		Ciphertext: sec,
	}, nil
}

// decrypt decrypts ciphertext using the provided secret.
func (p *processor) decrypt(ctx context.Context, req cryptor.DecryptRequest) (*cryptor.DecryptResponse, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, sreq *securemem.HandlerRequest) error {
		decResp, err := p.cryptor.Decrypt(ctx, req)
		if err != nil {
			return err
		}

		return sreq.PersistentVault().Import(persistSecName, decResp.Plaintext)
	})
	if err != nil {
		return nil, err
	}
	sec, err := getPersistedSec(resp)
	if err != nil {
		return nil, err
	}

	return &cryptor.DecryptResponse{
		Plaintext: sec,
	}, nil
}

// deleteSecret removes a secret from the vault.
func (p *processor) deleteSecret(ctx context.Context, req deleteSecretRequest) (deleteSecretResponse, error) {
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

// resolveSecret retrieves and unseals the secret for the given key version.
func (p *processor) resolveSecret(ctx context.Context, kv model.KeyVersion) (cryptor.Secret, error) {
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

		parentUnsealed, err := p.parentUnseal(ctx, kv, exported.KeyMaterial, exported.AAD)
		if err != nil {
			return err
		}
		defer destroySec(parentUnsealed)

		transUnsealed, err := p.transportUnseal(ctx, kv, parentUnsealed, exported.AAD)
		if err != nil {
			return err
		}
		defer destroySec(transUnsealed)

		// copy so that defers can unconditionally destroy all intermediates.
		sec, err := copySec(transUnsealed)
		if err != nil {
			return nil
		}

		return sreq.PersistentVault().Import(persistSecName, sec)
	})
	if err != nil {
		return cryptor.Secret{}, err
	}
	sec, err := getPersistedSec(resp)
	if err != nil {
		return cryptor.Secret{}, err
	}

	return cryptor.Secret{
		Algorithm: cryptor.KeyAlgorithmAES256,
		Data:      sec,
	}, nil
}

func (p *processor) transportSeal(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.transportSealer == nil {
		return sec, nil
	}
	resp, err := p.transportSealer.Seal(ctx, cryptor.SealRequest{
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

func (p *processor) transportUnseal(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if p.transportSealer == nil {
		return sec, nil
	}
	resp, err := p.transportSealer.Unseal(ctx, cryptor.UnsealRequest{
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

func (p *processor) parentSeal(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if kv.ParentKeyID == nil {
		return nil, ErrMissingParentKey
	}
	var parentVersion string
	if kv.ParentKeyVersion != nil {
		parentVersion = *kv.ParentKeyVersion
	}
	resp, err := p.parent.Seal(ctx, cryptor.SealRequest{
		TenantID:   kv.TenantID,
		KeyID:      *kv.ParentKeyID,
		KeyVersion: parentVersion,
		Plaintext:  sec,
		AAD:        aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (p *processor) parentUnseal(ctx context.Context, kv model.KeyVersion, sec *securemem.Data, aad []byte) (*securemem.Data, error) {
	if kv.ParentKeyID == nil {
		return nil, ErrMissingParentKey
	}
	var parentVersion string
	if kv.ParentKeyVersion != nil {
		parentVersion = *kv.ParentKeyVersion
	}
	resp, err := p.parent.Unseal(ctx, cryptor.UnsealRequest{
		TenantID:   kv.TenantID,
		KeyID:      *kv.ParentKeyID,
		KeyVersion: parentVersion,
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
