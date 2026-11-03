package keyprocessor

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

var (
	// ErrProviderNotAllowed means the provider type is not in the allowed set.
	ErrProviderNotAllowed = errors.New("provider is not allowed")
	// ErrProviderTypeMismatch means the requested provider type does not match the stored spec.
	ErrProviderTypeMismatch = errors.New("provider type does not match stored spec")
	// ErrNoProviderKeyVersion means no provider key version exists.
	ErrNoProviderKeyVersion = errors.New("no provider key version found")
	// ErrTransactorMissing means no transactor was supplied.
	ErrTransactorMissing = errors.New("transactor is required")
)

// RootManager seals and unseals the root key and manages its provider bindings.
type RootManager struct {
	transactor store.Transactor
	vault      vault.Vault
	allowed    map[sealer.Type]struct{}
}

var _ sealer.Sealer = &RootManager{}

// RootManagerConfig holds the root manager's dependencies: the transactor and
// the root key spec (its vault and allowed providers).
type RootManagerConfig struct {
	Transactor store.Transactor
	RootKey    spec.RootKeySpec
}

// NewRootManager resolves the root key's vault from its spec and returns a
// RootManager that seals the root key with the allowed providers.
func NewRootManager(ctx context.Context, cfg RootManagerConfig) (*RootManager, error) {
	if cfg.Transactor == nil {
		return nil, ErrTransactorMissing
	}

	v, err := vaultprovider.GetVault(ctx, cfg.RootKey.Vault)
	if err != nil {
		return nil, fmt.Errorf("root vault: %w", err)
	}

	allowed := make(map[sealer.Type]struct{}, len(cfg.RootKey.AllowedProviders))
	for _, t := range cfg.RootKey.AllowedProviders {
		allowed[t] = struct{}{}
	}

	return &RootManager{transactor: cfg.Transactor, vault: v, allowed: allowed}, nil
}

// CreateProviderInput is the input for CreateProvider.
type CreateProviderInput struct {
	TenantID      string
	KeyID         string
	Spec          sealerprovider.Spec
	ProviderKeyID string
}

// RotateAuthInput is the input for RotateAuth.
type RotateAuthInput struct {
	TenantID string
	KeyID    string
	Type     sealer.Type
	Auth     sealer.SealerAuth
}

// RotateProviderKeyInput is the input for RotateProviderKey.
type RotateProviderKeyInput struct {
	TenantID      string
	KeyID         string
	Type          sealer.Type
	ProviderKeyID string
}

// RemoveProviderInput is the input for RemoveProvider.
type RemoveProviderInput struct {
	TenantID string
	KeyID    string
}

// CreateProvider binds an allowed sealer provider to the key and records its first key version.
func (rm *RootManager) CreateProvider(ctx context.Context, in CreateProviderInput) error {
	if _, ok := rm.allowed[in.Spec.Type]; !ok {
		return ErrProviderNotAllowed
	}
	if err := in.Spec.Validate(); err != nil {
		return err
	}

	return store.ChainTransaction(ctx, rm.transactor,
		validator.ValidateTenant(in.TenantID),
		validator.ValidateKeyUsage(in.TenantID, in.KeyID, spec.KeyUsageLink),
		func(ctx context.Context, stores store.Stores) error {
			if err := rm.importSpec(ctx, in.TenantID, in.KeyID, in.Spec); err != nil {
				return err
			}

			pkv := providerKeyVersions{stores.KeyVersions, in.TenantID, in.KeyID}
			return pkv.create(ctx, 1, in.Spec.Type, in.ProviderKeyID)
		},
	)
}

// RotateAuth replaces the stored sealer auth for the key's provider.
func (rm *RootManager) RotateAuth(ctx context.Context, in RotateAuthInput) error {
	if err := in.Auth.ValidateSealerAuth(); err != nil {
		return err
	}

	return store.ChainTransaction(ctx, rm.transactor,
		validator.ValidateTenant(in.TenantID),
		validator.ValidateKeyUsage(in.TenantID, in.KeyID, spec.KeyUsageRotate),
		func(ctx context.Context, stores store.Stores) error {
			spec, err := rm.exportSpec(ctx, in.TenantID, in.KeyID)
			if err != nil {
				return err
			}
			if spec.Type != in.Type {
				return ErrProviderTypeMismatch
			}
			spec.Auth = in.Auth

			return rm.importSpec(ctx, in.TenantID, in.KeyID, spec)
		},
	)
}

// RotateProviderKey records a new provider key version for the key.
func (rm *RootManager) RotateProviderKey(ctx context.Context, in RotateProviderKeyInput) error {
	return store.ChainTransaction(ctx, rm.transactor,
		validator.ValidateTenant(in.TenantID),
		validator.ValidateKeyUsage(in.TenantID, in.KeyID, spec.KeyUsageRotate),
		func(ctx context.Context, stores store.Stores) error {
			spec, err := rm.exportSpec(ctx, in.TenantID, in.KeyID)
			if err != nil {
				return err
			}
			if spec.Type != in.Type {
				return ErrProviderTypeMismatch
			}

			pkv := providerKeyVersions{stores.KeyVersions, in.TenantID, in.KeyID}
			latest, err := pkv.latest(ctx)
			if err != nil {
				return err
			}

			return pkv.create(ctx, latest.Version+1, in.Type, in.ProviderKeyID)
		},
	)
}

// RemoveProvider removes the key's provider binding from the vault.
func (rm *RootManager) RemoveProvider(ctx context.Context, in RemoveProviderInput) error {
	return store.ChainTransaction(ctx, rm.transactor,
		validator.ValidateTenant(in.TenantID),
		func(ctx context.Context, stores store.Stores) error {
			return rm.destroySpec(ctx, in.TenantID, in.KeyID)
		},
	)
}

// Seal seals the request using the key's configured provider.
func (rm *RootManager) Seal(ctx context.Context, req sealer.SealRequest) (sealer.SealResponse, error) {
	if req.KeyVersion == 0 {
		return sealer.SealResponse{}, ErrKeyVersionRequired
	}

	var resp sealer.SealResponse
	err := store.ChainTransaction(ctx, rm.transactor,
		validator.ValidateTenant(req.TenantID),
		validator.ValidateKeyUsage(req.TenantID, req.KeyID, spec.KeyUsageEncrypt),
		func(ctx context.Context, stores store.Stores) error {
			sp, err := rm.exportSpec(ctx, req.TenantID, req.KeyID)
			if err != nil {
				return err
			}

			s, err := sealerprovider.GetSealer(ctx, sp)
			if err != nil {
				return err
			}

			pkv := providerKeyVersions{stores.KeyVersions, req.TenantID, req.KeyID}
			label, err := pkv.resolveLabel(ctx, req.KeyVersion, sp.Type)
			if err != nil {
				return err
			}
			if req.Metadata == nil {
				req.Metadata = map[string]string{}
			}
			req.Metadata[providerKeyLabel(sp.Type)] = label

			resp, err = s.Seal(ctx, req)
			return err
		},
	)
	return resp, err
}

// Unseal unseals the request using the key's configured provider.
func (rm *RootManager) Unseal(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
	if req.KeyVersion == 0 {
		return sealer.UnsealResponse{}, ErrKeyVersionRequired
	}

	var resp sealer.UnsealResponse
	err := store.ChainTransaction(ctx, rm.transactor,
		validator.ValidateTenant(req.TenantID),
		validator.ValidateKeyUsage(req.TenantID, req.KeyID, spec.KeyUsageDecrypt),
		func(ctx context.Context, stores store.Stores) error {
			sp, err := rm.exportSpec(ctx, req.TenantID, req.KeyID)
			if err != nil {
				return err
			}

			s, err := sealerprovider.GetSealer(ctx, sp)
			if err != nil {
				return err
			}

			pkv := providerKeyVersions{stores.KeyVersions, req.TenantID, req.KeyID}
			label, err := pkv.resolveLabel(ctx, req.KeyVersion, sp.Type)
			if err != nil {
				return err
			}
			if req.Metadata == nil {
				req.Metadata = map[string]string{}
			}
			req.Metadata[providerKeyLabel(sp.Type)] = label

			resp, err = s.Unseal(ctx, req)
			return err
		},
	)
	return resp, err
}

func (rm *RootManager) importSpec(ctx context.Context, tenantID, keyID string, spec sealerprovider.Spec) error {
	b, err := yaml.Marshal(&spec)
	if err != nil {
		return err
	}
	defer securemem.Zero(b)

	d, err := securemem.NewData("spec", len(b))
	if err != nil {
		return err
	}
	defer d.Destroy()
	copy(d.SecureBytes(), b)

	_, err = rm.vault.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    tenantID,
		KeyID:       keyID,
		KeyMaterial: d,
	})
	return err
}

func (rm *RootManager) exportSpec(ctx context.Context, tenantID, keyID string) (sealerprovider.Spec, error) {
	resp, err := rm.vault.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID: tenantID,
		KeyID:    keyID,
	})
	if err != nil {
		return sealerprovider.Spec{}, err
	}
	defer resp.KeyMaterial.Destroy()

	spec := sealerprovider.Spec{}
	err = yaml.Unmarshal(resp.KeyMaterial.SecureBytes(), &spec)
	return spec, err
}

func (rm *RootManager) destroySpec(ctx context.Context, tenantID, keyID string) error {
	_, err := rm.vault.DestroyKey(ctx, vault.DestroyKeyRequest{
		TenantID: tenantID,
		KeyID:    keyID,
	})
	return err
}

type providerKeyVersions struct {
	versions store.KeyVersion
	tenantID string
	keyID    string
}

func (p providerKeyVersions) fetchOne(ctx context.Context, q store.ListKeyVersionsQuery) (model.KeyVersion, error) {
	q.TenantID = p.tenantID
	q.KeyID = p.keyID
	q.Limit = 1

	res, err := p.versions.ListKeyVersions(ctx, q)
	if err != nil {
		return model.KeyVersion{}, err
	}
	if len(res.KeyVersions) == 0 {
		return model.KeyVersion{}, ErrNoProviderKeyVersion
	}
	return res.KeyVersions[0], nil
}

func (p providerKeyVersions) latest(ctx context.Context) (model.KeyVersion, error) {
	return p.fetchOne(ctx, store.ListKeyVersionsQuery{
		OrderBy: []store.KeyVersionOrder{store.KeyVersionOrderVersionDesc},
	})
}

func (p providerKeyVersions) resolveLabel(ctx context.Context, version int, t sealer.Type) (string, error) {
	kv, err := p.fetchOne(ctx, store.ListKeyVersionsQuery{
		Version: version,
		OrderBy: []store.KeyVersionOrder{store.KeyVersionOrderRevisionDesc},
	})
	if err != nil {
		return "", err
	}
	return kv.Labels[providerKeyLabel(t)], nil
}

func (p providerKeyVersions) create(ctx context.Context, version int, t sealer.Type, providerKeyID string) error {
	labels := map[string]string{
		providerKeyLabel(t): providerKeyID,
	}
	v := model.NewKeyVersion(p.tenantID, p.keyID, version, nil, nil).WithLabels(labels)
	_, err := p.versions.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{KeyVersion: v})
	return err
}

func providerKeyLabel(t sealer.Type) string {
	return model.ReservedLabelPrefix + string(t) + ":provider-key"
}
