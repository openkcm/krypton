package openbaovault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	openbao "github.com/openbao/openbao/api/v2"

	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
)

const kvSecretName = "kv-secrets"

const securememImportKey = "key_material"

// Options is a function type that can be used to configure the OpenBao client.
type Options func(*openbao.Client) error

// Vault is an implementation of the vault.Vault interface that uses OpenBao as the backend.
type Vault struct {
	info vault.Info
	cli  *openbao.Client
}

type data struct {
	KeyMaterial string `mapstructure:"key_material"`
	AAD         string `mapstructure:"aad"`
}

var kvCreateRequest = map[string]any{
	"type": "kv",
	"options": map[string]any{
		"version": "1",
	},
}

var errAllocatedDataNotFound = errors.New("allocated data not found in vault")

var _ vault.Vault = (*Vault)(nil)

// New creates a new instance of the OpenBao vault.
func New(name string, opts ...Options) (*Vault, error) {
	client, err := openbao.NewClient(openbao.DefaultConfig())
	if err != nil {
		return nil, err
	}

	for _, opt := range opts {
		if opt == nil {
			continue
		}
		err = opt(client)
		if err != nil {
			return nil, err
		}
	}

	return &Vault{
		info: vault.Info{
			Name: name,
			Type: TypeOpenBao,
		},
		cli: client,
	}, nil
}

// PrepareTenant creates a namespace and mounts the kv secret engine for the tenant.
func (v *Vault) PrepareTenant(ctx context.Context, req vault.PrepareTenantRequest) (*vault.PrepareTenantResponse, error) {
	// create the namespace for the tenant
	_, err := v.cli.Logical().WriteWithContext(ctx, namespacePath(req.TenantID), map[string]any{})
	if err != nil {
		return nil, err
	}

	// mount the kv secret engine for the tenant
	_, err = v.cli.Logical().WriteWithContext(ctx, kvSecretPath(req.TenantID), kvCreateRequest)
	if err != nil && !isKVPathExists(err) {
		return nil, err
	}
	return &vault.PrepareTenantResponse{}, nil
}

// DestroyTenant removes the namespace and kv secret engine for the tenant.
func (v *Vault) DestroyTenant(ctx context.Context, req vault.DestroyTenantRequest) (*vault.DestroyTenantResponse, error) {
	_, err := v.cli.Logical().DeleteWithContext(ctx, kvSecretPath(req.TenantID))
	if err != nil && !isKVPathDeleted(err) {
		return nil, err
	}

	_, err = v.cli.Logical().DeleteWithContext(ctx, namespacePath(req.TenantID))
	if err != nil {
		return nil, err
	}
	return &vault.DestroyTenantResponse{}, nil
}

// ImportKey stores the key material in the vault.
func (v *Vault) ImportKey(ctx context.Context, req vault.ImportKeyRequest) (*vault.ImportKeyResponse, error) {
	if req.KeyMaterial == nil {
		return nil, vault.ErrInvalidRequest
	}
	_, err := securemem.Run(ctx, func(ctx context.Context, hreq *securemem.HandlerRequest) error {
		data, err := toKvData(data{KeyMaterial: base64Encode(req.KeyMaterial.SecureBytes()), AAD: base64Encode(req.AAD)})
		if err != nil {
			return err
		}
		return v.cli.KVv1(kvMountPath(req.TenantID)).
			Put(
				ctx,
				kvPath(req.KeyID, req.KeyVersion),
				data,
			)
	})
	if err != nil {
		return nil, err
	}
	return &vault.ImportKeyResponse{}, nil
}

// ExportKey retrieves the key material from the vault.
func (v *Vault) ExportKey(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
	var aad []byte

	resp, err := securemem.Run(ctx, func(ctx context.Context, hreq *securemem.HandlerRequest) error {
		data, err := v.cli.KVv1(kvMountPath(req.TenantID)).
			Get(ctx, kvPath(req.KeyID, req.KeyVersion))
		if err != nil {
			return err
		}

		kvData, err := toData(data.Data)
		if err != nil {
			return err
		}

		b64Km, err := base64Decode(kvData.KeyMaterial)
		if err != nil {
			return err
		}

		// clear the temporary buffer to avoid leaving sensitive data in memory
		defer securemem.Zero(b64Km)

		sKm, err := hreq.PersistentVault().Reserve(securememImportKey, len(b64Km))
		if err != nil {
			return err
		}

		copy(sKm, b64Km)

		aad, err = base64Decode(kvData.AAD)
		return err
	})

	if err != nil {
		if errors.Is(err, openbao.ErrSecretNotFound) {
			return nil, vault.ErrKeyNotFound
		}
		return nil, err
	}

	data, ok := resp.MemVault().Get(securememImportKey)
	if !ok {
		err := resp.MemVault().DestroyAll()
		if err != nil {
			return nil, err
		}
		return nil, errAllocatedDataNotFound
	}

	return &vault.ExportKeyResponse{
		KeyMaterial: data,
		AAD:         aad,
	}, nil
}

// DestroyKey removes the key material from the vault.
func (v *Vault) DestroyKey(ctx context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
	err := v.cli.KVv1(kvMountPath(req.TenantID)).
		Delete(ctx, kvPath(req.KeyID, req.KeyVersion))
	if err != nil && !isKVPathDeleted(err) {
		return nil, err
	}
	return &vault.DestroyKeyResponse{}, nil
}

// Info returns the vault information.
func (v *Vault) Info() vault.Info {
	return v.info
}

func toKvData(d data) (map[string]any, error) {
	result := map[string]any{}
	err := mapstructure.Decode(d, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func toData(kv map[string]any) (*data, error) {
	d := data{}
	err := mapstructure.Decode(kv, &d)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func base64Encode[T securemem.SecureBytes | []byte](b T) string {
	return base64.StdEncoding.EncodeToString(b)
}

func base64Decode(b string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(b)
}

func isKVPathDeleted(err error) bool {
	var respErr *openbao.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound {
		return true
	}
	return false
}

func isKVPathExists(err error) bool {
	var respErr *openbao.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == http.StatusBadRequest {
		for _, e := range respErr.Errors {
			if strings.Contains(e, fmt.Sprintf("path is already in use at %s/", kvSecretName)) {
				return true
			}
		}
	}
	return false
}

func kvMountPath(tenantID string) string {
	return fmt.Sprintf("%s/%s", tenantID, kvSecretName)
}

func kvPath(keyID, keyVersion string) string {
	return fmt.Sprintf("%s/%s", keyID, keyVersion)
}

func kvSecretPath(tenantID string) string {
	return tenantID + "/sys/mounts/" + kvSecretName
}

func namespacePath(tenantID string) string {
	return "sys/namespaces/" + tenantID
}
