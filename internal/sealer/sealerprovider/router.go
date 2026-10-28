package sealerprovider

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
)

const TypeSealerRouter sealer.Type = "krypton-sealer-router"

const configBlobKey = "router-config-blob"

const resultKey = "router-result"

var (
	ErrProviderTypeNotAllowed = errors.New("provider type not allowed")
	ErrAllowedTypesEmpty      = errors.New("allowed_types must not be empty")
	errResultMissing          = errors.New("router result missing from secure vault")
)

type Config struct {
	AllowedTypes []string           `yaml:"allowed_types"`
	Vault        vaultprovider.Spec `yaml:"vault"`
	Sealer       Spec               `yaml:"sealer"`
}

var _ sealer.SealerConfig = (*Config)(nil)

func (c *Config) ValidateSealerConfig() error {
	if len(c.AllowedTypes) == 0 {
		return ErrAllowedTypesEmpty
	}
	if err := c.Vault.Validate(); err != nil {
		return err
	}
	return c.Sealer.Validate()
}

type identity struct {
	TenantID   string `json:"tenant_id"`
	KeyID      string `json:"key_id"`
	ExternalID string `json:"external_id"`
}

type LinkKeyRequest struct {
	Spec       Spec
	TenantID   string
	KeyID      string
	ExternalID string
}

type UnlinkKeyRequest struct {
	TenantID string
	KeyID    string
}

type Router struct {
	allowedTypes map[string]struct{}
	vault        vault.Vault
	sealer       sealer.Sealer
}

var _ sealer.Sealer = (*Router)(nil)

func New(cfg Config, v vault.Vault, s sealer.Sealer) (*Router, error) {
	allowed := make(map[string]struct{}, len(cfg.AllowedTypes))
	for _, t := range cfg.AllowedTypes {
		allowed[t] = struct{}{}
	}
	return &Router{
		allowedTypes: allowed,
		vault:        v,
		sealer:       s,
	}, nil
}

func (r *Router) LinkKey(ctx context.Context, req LinkKeyRequest) error {
	if _, ok := r.allowedTypes[string(req.Spec.Type)]; !ok {
		return fmt.Errorf("%w: %q", ErrProviderTypeNotAllowed, req.Spec.Type)
	}

	aad, err := json.Marshal(identity{
		TenantID:   req.TenantID,
		KeyID:      req.KeyID,
		ExternalID: req.ExternalID,
	})
	if err != nil {
		return err
	}

	_, err = securemem.Run(ctx, func(ctx context.Context, _ *securemem.HandlerRequest) error {
		blob, err := marshalSpec(req.Spec)
		if err != nil {
			return err
		}
		defer blob.Destroy()

		sealed, err := r.sealer.Seal(ctx, sealer.SealRequest{
			TenantID:   req.TenantID,
			KeyID:      req.KeyID,
			KeyVersion: 0,
			Plaintext:  blob,
			AAD:        aad,
		})
		if err != nil {
			return err
		}
		defer sealed.Ciphertext.Destroy()

		_, err = r.vault.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    req.TenantID,
			KeyID:       req.KeyID,
			KeyVersion:  0,
			KeyRevision: 0,
			KeyMaterial: sealed.Ciphertext,
			AAD:         aad,
		})
		return err
	})
	return err
}

func (r *Router) UnlinkKey(ctx context.Context, req UnlinkKeyRequest) error {
	_, err := r.vault.DestroyKey(ctx, vault.DestroyKeyRequest{
		TenantID:    req.TenantID,
		KeyID:       req.KeyID,
		KeyVersion:  0,
		KeyRevision: 0,
	})
	return err
}

func (r *Router) Seal(ctx context.Context, req sealer.SealRequest) (sealer.SealResponse, error) {
	out, err := r.withSealer(ctx, req.TenantID, req.KeyID, func(ctx context.Context, s sealer.Sealer) (*securemem.Data, error) {
		resp, err := s.Seal(ctx, req)
		if err != nil {
			return nil, err
		}
		return resp.Ciphertext, nil
	})
	if err != nil {
		return sealer.SealResponse{}, err
	}
	return sealer.SealResponse{Ciphertext: out}, nil
}

func (r *Router) Unseal(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
	out, err := r.withSealer(ctx, req.TenantID, req.KeyID, func(ctx context.Context, s sealer.Sealer) (*securemem.Data, error) {
		resp, err := s.Unseal(ctx, req)
		if err != nil {
			return nil, err
		}
		return resp.Plaintext, nil
	})
	if err != nil {
		return sealer.UnsealResponse{}, err
	}
	return sealer.UnsealResponse{Plaintext: out}, nil
}

func (r *Router) withSealer(
	ctx context.Context,
	tenantID, keyID string,
	fn func(context.Context, sealer.Sealer) (*securemem.Data, error),
) (*securemem.Data, error) {
	resp, err := securemem.Run(ctx, func(ctx context.Context, hreq *securemem.HandlerRequest) error {
		exported, err := r.vault.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  0,
			KeyRevision: 0,
		})
		if err != nil {
			return err
		}
		defer exported.KeyMaterial.Destroy()

		unsealed, err := r.sealer.Unseal(ctx, sealer.UnsealRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: 0,
			Ciphertext: exported.KeyMaterial,
			AAD:        exported.AAD,
		})
		if err != nil {
			return err
		}
		defer unsealed.Plaintext.Destroy()

		spec, err := unmarshalSpec(unsealed.Plaintext)
		if err != nil {
			return err
		}
		defer spec.DestroySecret()

		s, err := GetSealer(ctx, spec)
		if err != nil {
			return err
		}

		out, err := fn(ctx, s)
		if err != nil {
			return err
		}
		return hreq.PersistentVault().Import(resultKey, out)
	})
	if err != nil {
		return nil, err
	}

	data, ok := resp.MemVault().Get(resultKey)
	if !ok {
		_ = resp.MemVault().DestroyAll()
		return nil, errResultMissing
	}
	return data, nil
}

func marshalSpec(spec Spec) (*securemem.Data, error) {
	raw, err := yaml.Marshal(&spec)
	if err != nil {
		return nil, err
	}
	defer securemem.Zero(raw)

	data, err := securemem.NewData(configBlobKey, len(raw))
	if err != nil {
		return nil, err
	}
	copy(data.SecureBytes(), raw)
	return data, nil
}

func unmarshalSpec(blob *securemem.Data) (Spec, error) {
	var spec Spec
	if err := yaml.Unmarshal(blob.SecureBytes(), &spec); err != nil {
		return Spec{}, err
	}
	return spec, nil
}
