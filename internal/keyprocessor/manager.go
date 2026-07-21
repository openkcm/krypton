package keyprocessor

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

var (
	// ErrProcessorNotFound is returned when no processor is registered for a key's kind.
	ErrProcessorNotFound = errors.New("key processor could not be found")
	// ErrNoUsableKeyVersion is returned when no usable key version can be resolved.
	ErrNoUsableKeyVersion = errors.New("no usable key version found")
)

// Manager wraps and unwraps secrets by resolving the appropriate KeyVersion
// from the store and delegating to the Processor registered for that key's kind.
type Manager struct {
	store        store.Key
	versionStore store.KeyVersion
	processors   map[model.KeyKind]Processor
}

var _ SecretWrapper = &Manager{}

// WrapSecret resolves the key version and delegates to the matching processor.
func (km *Manager) WrapSecret(ctx context.Context, req SecretWrapRequest) (*SecretWrapResponse, error) {
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
		Secret:     req.Secret,
		AAD:        req.AAD,
	})
	if err != nil {
		return nil, err
	}

	return &SecretWrapResponse{
		WrappedSecret: resp.WrappedSecret,
	}, nil
}

// UnwrapSecret resolves the key version and delegates to the matching processor.
func (km *Manager) UnwrapSecret(ctx context.Context, req SecretUnwrapRequest) (*SecretUnwrapResponse, error) {
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
		WrappedSecret: req.WrappedSecret,
		AAD:           req.AAD,
	})
	if err != nil {
		return nil, err
	}

	return &SecretUnwrapResponse{
		Secret: resp.Secret,
	}, nil
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
