package keyprocessor

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

var (
	// ErrProcessorNotFound is returned when no processor is registered for a key's kind.
	ErrProcessorNotFound = errors.New("key processor could not be found")
	// ErrNoUsableKeyVersion is returned when no usable key version can be resolved.
	ErrNoUsableKeyVersion = errors.New("no usable key version found")
)

// TypeManager identifies the Manager cryptor type.
const TypeManager cryptor.Type = "manager"

// Manager encrypts and decrypts secrets by resolving the appropriate KeyVersion
// from the store and delegating to the Processor registered for that key's kind.
type Manager struct {
	store        store.Key
	versionStore store.KeyVersion
	processors   map[model.KeyKind]Processor
}

var _ cryptor.Cryptor = &Manager{}

// Encrypt resolves the key version and delegates to the matching processor.
func (km *Manager) Encrypt(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
	kv, err := km.resolveUsableKeyVersion(ctx, req.TenantID, req.KeyID, req.KeyVersion)
	if err != nil {
		return nil, err
	}

	key, err := km.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return nil, err
	}
	proc, ok := km.processors[key.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: key kind %s", ErrProcessorNotFound, key.Kind)
	}

	resp, err := proc.WrapSecret(ctx, WrapSecretRequest{
		KeyVersion: kv,
		Secret:     req.Plaintext,
		AAD:        req.AAD,
	})
	if err != nil {
		return nil, err
	}

	return &cryptor.EncryptResponse{
		Ciphertext: resp.WrappedSecret,
	}, nil
}

// Decrypt resolves the key version and delegates to the matching processor.
func (km *Manager) Decrypt(ctx context.Context, req cryptor.DecryptRequest) (*cryptor.DecryptResponse, error) {
	kv, err := km.resolveUsableKeyVersion(ctx, req.TenantID, req.KeyID, req.KeyVersion)
	if err != nil {
		return nil, err
	}

	key, err := km.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return nil, err
	}
	proc, ok := km.processors[key.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: key kind %s", ErrProcessorNotFound, key.Kind)
	}

	resp, err := proc.UnwrapSecret(ctx, UnwrapSecretRequest{
		KeyVersion:    kv,
		WrappedSecret: req.Ciphertext,
		AAD:           req.AAD,
	})
	if err != nil {
		return nil, err
	}

	return &cryptor.DecryptResponse{
		Plaintext: resp.Secret,
	}, nil
}

// Info returns the Manager's cryptor metadata.
func (km *Manager) Info() cryptor.Info {
	return cryptor.Info{
		Name:                     "keyprocessor-manager",
		Type:                     TypeManager,
		DecryptionSecretRequired: true,
	}
}

func (km *Manager) resolveUsableKeyVersion(ctx context.Context, tenantID, keyID, version string) (model.KeyVersion, error) {
	result, err := km.versionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
		TenantID:              tenantID,
		KeyID:                 keyID,
		Version:               version,
		ProcessingState:       model.KeyVersionUsable,
		IsOrderByRevisionDesc: true,
		Limit:                 1,
	})
	if err != nil {
		return model.KeyVersion{}, err
	}
	if len(result.KeyVersions) == 0 {
		return model.KeyVersion{}, fmt.Errorf("%w: key %s version %s", ErrNoUsableKeyVersion, keyID, version)
	}
	return result.KeyVersions[0], nil
}
