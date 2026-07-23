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
	// ErrKeyNotActivated is returned when the key is not in an active lifecycle state.
	ErrKeyNotActivated = errors.New("key is not in activated state")
	// ErrKeyVersionRequired is returned when the key version is not specified.
	ErrKeyVersionRequired = errors.New("key version is required")
)

// Manager validates the key lifecycle, resolves key versions, and delegates to processors.
type Manager struct {
	store        store.Key
	versionStore store.KeyVersion
	processors   map[model.KeyKind]processor
}

var _ cryptor.Sealer = &Manager{}

// Seal validates the key lifecycle, resolves the key version and its secret to encrypt the plaintext.
func (km *Manager) Seal(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
	if req.KeyVersion == nil {
		return cryptor.SealResponse{}, ErrKeyVersionRequired
	}
	kv, err := km.resolveUsableKeyVersion(ctx, req.TenantID, req.KeyID, *req.KeyVersion)
	if err != nil {
		return cryptor.SealResponse{}, err
	}

	key, err := km.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return cryptor.SealResponse{}, err
	}
	if key.LifeCycleState != model.KeyLifeCycleActive {
		return cryptor.SealResponse{}, fmt.Errorf("%w: key %s is in state %s", ErrKeyNotActivated, key.ID, key.LifeCycleState)
	}
	proc, ok := km.processors[key.Kind]
	if !ok {
		return cryptor.SealResponse{}, fmt.Errorf("%w: key kind %s", ErrProcessorNotFound, key.Kind)
	}

	sec, err := proc.resolveSecret(ctx, kv)
	if err != nil {
		return cryptor.SealResponse{}, err
	}
	defer destroySec(sec.Data)

	resp, err := proc.encrypt(ctx, cryptor.EncryptRequest{
		Secret:    sec,
		Plaintext: req.Plaintext,
		AAD:       req.AAD,
	})
	if err != nil {
		return cryptor.SealResponse{}, err
	}

	return cryptor.SealResponse{
		Ciphertext: resp.Ciphertext,
	}, nil
}

// Unseal validates the key lifecycle, resolves the key version and its secret to decrypt the ciphertext.
func (km *Manager) Unseal(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
	if req.KeyVersion == nil {
		return cryptor.UnsealResponse{}, ErrKeyVersionRequired
	}
	kv, err := km.resolveUsableKeyVersion(ctx, req.TenantID, req.KeyID, *req.KeyVersion)
	if err != nil {
		return cryptor.UnsealResponse{}, err
	}

	key, err := km.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return cryptor.UnsealResponse{}, err
	}
	if key.LifeCycleState != model.KeyLifeCycleActive {
		return cryptor.UnsealResponse{}, fmt.Errorf("%w: key %s is in state %s", ErrKeyNotActivated, key.ID, key.LifeCycleState)
	}
	proc, ok := km.processors[key.Kind]
	if !ok {
		return cryptor.UnsealResponse{}, fmt.Errorf("%w: key kind %s", ErrProcessorNotFound, key.Kind)
	}

	sec, err := proc.resolveSecret(ctx, kv)
	if err != nil {
		return cryptor.UnsealResponse{}, err
	}
	defer destroySec(sec.Data)

	resp, err := proc.decrypt(ctx, cryptor.DecryptRequest{
		Secret:     sec,
		Ciphertext: req.Ciphertext,
		AAD:        req.AAD,
	})
	if err != nil {
		return cryptor.UnsealResponse{}, err
	}

	return cryptor.UnsealResponse{
		Plaintext: resp.Plaintext,
	}, nil
}

// RootManager validates key lifecycle and delegates to a sealer for root keys
// that manage their own secret.
type RootManager struct {
	store  store.Key
	sealer cryptor.Sealer
}

var _ cryptor.Sealer = &RootManager{}

// Seal validates the key lifecycle and seals the plaintext using the underlying sealer.
func (rm *RootManager) Seal(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
	key, err := rm.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return cryptor.SealResponse{}, err
	}
	if key.LifeCycleState != model.KeyLifeCycleActive {
		return cryptor.SealResponse{}, fmt.Errorf("%w: key %s is in state %s", ErrKeyNotActivated, key.ID, key.LifeCycleState)
	}

	return rm.sealer.Seal(ctx, req)
}

// Unseal validates the key lifecycle and unseals the ciphertext using the underlying sealer.
func (rm *RootManager) Unseal(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
	key, err := rm.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return cryptor.UnsealResponse{}, err
	}
	if key.LifeCycleState != model.KeyLifeCycleActive {
		return cryptor.UnsealResponse{}, fmt.Errorf("%w: key %s is in state %s", ErrKeyNotActivated, key.ID, key.LifeCycleState)
	}

	return rm.sealer.Unseal(ctx, req)
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
