package keyprocessor

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/spec"
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
	// ErrRootMissingSealerSpec is returned when the root key binding has no sealer spec.
	ErrRootMissingSealerSpec = errors.New("root key binding must have a sealer spec")
	// ErrKeyStoreMissing is returned when the key store is nil.
	ErrKeyStoreMissing = errors.New("key store is required")
	// ErrKeyVersionStoreMissing is returned when the key version store is nil.
	ErrKeyVersionStoreMissing = errors.New("key version store is required")
)

// ManagerConfig holds the dependencies needed to construct a Manager.
type ManagerConfig struct {
	KeyStore        store.Key
	KeyVersionStore store.KeyVersion
	Bindings        map[model.KeyKind]spec.KeyBinding
	Hierarchy       spec.KeyHierarchy
}

// Manager validates the key lifecycle, resolves key versions, and delegates to processors.
type Manager struct {
	store        store.Key
	versionStore store.KeyVersion
	processors   map[model.KeyKind]processor
}

var _ cryptor.Sealer = &Manager{}

// NewManager constructs a Manager by resolving the root sealer and building
// a processor for each non-root key kind defined in the hierarchy.
func NewManager(ctx context.Context, cfg ManagerConfig) (*Manager, error) {
	if cfg.KeyStore == nil {
		return nil, ErrKeyStoreMissing
	}
	if cfg.KeyVersionStore == nil {
		return nil, ErrKeyVersionStoreMissing
	}

	mgr := &Manager{
		store:        cfg.KeyStore,
		versionStore: cfg.KeyVersionStore,
	}

	rootMgr, err := buildRootManager(ctx, cfg.KeyStore, cfg.Bindings, cfg.Hierarchy)
	if err != nil {
		return nil, err
	}

	processors, err := buildProcessors(ctx, cfg.Hierarchy, cfg.Bindings, rootMgr, mgr)
	if err != nil {
		return nil, err
	}

	mgr.processors = processors
	return mgr, nil
}

func buildRootManager(ctx context.Context, s store.Key, bindings map[model.KeyKind]spec.KeyBinding, hierarchy spec.KeyHierarchy) (*rootManager, error) {
	for _, ks := range hierarchy.KeySpecs {
		if ks.Role != spec.KeyRoleRoot {
			continue
		}

		binding, ok := bindings[ks.Kind]
		if !ok {
			return nil, fmt.Errorf("no binding found for root key kind %s", ks.Kind)
		}
		if binding.SealerSpec == nil {
			return nil, ErrRootMissingSealerSpec
		}

		sealer, err := sealerprovider.GetSealer(ctx, *binding.SealerSpec)
		if err != nil {
			return nil, err
		}

		return &rootManager{store: s, sealer: sealer}, nil
	}

	return nil, fmt.Errorf("no root key spec found in hierarchy %q", hierarchy.Name)
}

func buildProcessors(ctx context.Context, hierarchy spec.KeyHierarchy, bindings map[model.KeyKind]spec.KeyBinding, rootMgr *rootManager, mgr *Manager) (map[model.KeyKind]processor, error) {
	processors := make(map[model.KeyKind]processor, len(bindings))

	prevRole := spec.KeyRole("")
	for _, ks := range hierarchy.KeySpecs {
		if ks.Role == spec.KeyRoleRoot {
			prevRole = ks.Role
			continue
		}

		binding, ok := bindings[ks.Kind]
		if !ok {
			return nil, fmt.Errorf("no binding found for key kind %s", ks.Kind)
		}

		var parent cryptor.Sealer
		if prevRole == spec.KeyRoleRoot {
			parent = rootMgr
		} else {
			parent = mgr
		}
		prevRole = ks.Role

		proc, err := newProcessor(ctx, binding, parent)
		if err != nil {
			return nil, fmt.Errorf("building processor for key kind %s: %w", ks.Kind, err)
		}

		processors[ks.Kind] = *proc
	}

	return processors, nil
}

// ExportSecretRequest identifies the key whose plaintext material to export.
type ExportSecretRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion string
}

// ExportSecret returns the plaintext key material for an active key's usable
// version. The returned Secret.Data is caller-owned and must be destroyed.
func (km *Manager) ExportSecret(ctx context.Context, req ExportSecretRequest) (cryptor.Secret, error) {
	_, sec, err := km.resolveProcessorAndSecret(ctx, req.TenantID, req.KeyID, req.KeyVersion)
	return sec, err
}

// resolveProcessorAndSecret resolves a usable key version, checks the key
// lifecycle, and unseals its secret via the processor for the key's kind.
func (km *Manager) resolveProcessorAndSecret(ctx context.Context, tenantID, keyID, version string) (processor, cryptor.Secret, error) {
	kv, err := km.resolveUsableKeyVersion(ctx, tenantID, keyID, version)
	if err != nil {
		return processor{}, cryptor.Secret{}, err
	}

	key, err := km.store.GetKeyByID(ctx, keyID, tenantID)
	if err != nil {
		return processor{}, cryptor.Secret{}, err
	}
	if key.LifeCycleState != model.KeyLifeCycleActive {
		return processor{}, cryptor.Secret{}, fmt.Errorf("%w: key %s is in state %s", ErrKeyNotActivated, key.ID, key.LifeCycleState)
	}
	proc, ok := km.processors[key.Kind]
	if !ok {
		return processor{}, cryptor.Secret{}, fmt.Errorf("%w: key kind %s", ErrProcessorNotFound, key.Kind)
	}

	sec, err := proc.resolveSecret(ctx, kv)
	if err != nil {
		return processor{}, cryptor.Secret{}, err
	}
	return proc, sec, nil
}

// Seal validates the key lifecycle, resolves the key version and its secret to encrypt the plaintext.
func (km *Manager) Seal(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
	if req.KeyVersion == "" {
		return cryptor.SealResponse{}, ErrKeyVersionRequired
	}
	proc, sec, err := km.resolveProcessorAndSecret(ctx, req.TenantID, req.KeyID, req.KeyVersion)
	if err != nil {
		return cryptor.SealResponse{}, err
	}
	defer sec.Data.Destroy()

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
	if req.KeyVersion == "" {
		return cryptor.UnsealResponse{}, ErrKeyVersionRequired
	}
	proc, sec, err := km.resolveProcessorAndSecret(ctx, req.TenantID, req.KeyID, req.KeyVersion)
	if err != nil {
		return cryptor.UnsealResponse{}, err
	}
	defer sec.Data.Destroy()

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

type rootManager struct {
	store  store.Key
	sealer cryptor.Sealer
}

var _ cryptor.Sealer = &rootManager{}

func (rm *rootManager) Seal(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
	key, err := rm.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return cryptor.SealResponse{}, err
	}
	if key.LifeCycleState != model.KeyLifeCycleActive {
		return cryptor.SealResponse{}, fmt.Errorf("%w: key %s is in state %s", ErrKeyNotActivated, key.ID, key.LifeCycleState)
	}

	return rm.sealer.Seal(ctx, req)
}

func (rm *rootManager) Unseal(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
	key, err := rm.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return cryptor.UnsealResponse{}, err
	}
	if key.LifeCycleState != model.KeyLifeCycleActive {
		return cryptor.UnsealResponse{}, fmt.Errorf("%w: key %s is in state %s", ErrKeyNotActivated, key.ID, key.LifeCycleState)
	}

	return rm.sealer.Unseal(ctx, req)
}

// resolveUsableKeyVersion returns the highest usable revision of version, or
// the most recently created usable version when version is empty. Rotation
// work must replace the latter with an explicit current-version marker.
func (km *Manager) resolveUsableKeyVersion(ctx context.Context, tenantID, keyID, version string) (model.KeyVersion, error) {
	orderBy := []store.KeyVersionOrder{store.KeyVersionOrderRevisionDesc}
	if version == "" {
		orderBy = []store.KeyVersionOrder{
			store.KeyVersionOrderCreatedAtDesc,
			store.KeyVersionOrderRevisionDesc,
		}
	}
	result, err := km.versionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
		TenantID:        tenantID,
		KeyID:           keyID,
		Version:         version,
		ProcessingState: model.KeyVersionUsable,
		OrderBy:         orderBy,
		Limit:           1,
	})
	if err != nil {
		return model.KeyVersion{}, err
	}
	if len(result.KeyVersions) == 0 {
		return model.KeyVersion{}, fmt.Errorf("%w: key %s version %s", ErrNoUsableKeyVersion, keyID, version)
	}
	return result.KeyVersions[0], nil
}
