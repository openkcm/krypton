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

const securememImportSecret = "secret"

// Options is a function type that can be used to configure the OpenBao client.
type Options func(*openbao.Client) error

// Vault is an implementation of the vault.Vault interface that uses OpenBao as the backend.
type Vault struct {
	info vault.Info
	cli  *openbao.Client
}

type data struct {
	Secret   string `mapstructure:"secret"`
	Metadata string `mapstructure:"metadata"`
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

// ImportSecret stores the secret in the vault.
func (v *Vault) ImportSecret(ctx context.Context, req vault.ImportSecretRequest) (*vault.ImportSecretResponse, error) {
	if req.Secret == nil {
		return nil, vault.ErrInvalidRequest
	}
	_, err := securemem.Run(ctx, func(ctx context.Context, hreq *securemem.HandlerRequest) error {
		data, err := toKvData(data{Secret: base64Encode(req.Secret.SecureBytes()), Metadata: base64Encode(req.Metadata)})
		if err != nil {
			return err
		}
		return v.cli.KVv1(kvMountPath(req.TenantID)).
			Put(
				ctx,
				kvPath(req.ID, req.Version, req.Revision),
				data,
			)
	})
	if err != nil {
		return nil, err
	}
	return &vault.ImportSecretResponse{}, nil
}

// ExportSecret retrieves the secret from the vault.
func (v *Vault) ExportSecret(ctx context.Context, req vault.ExportSecretRequest) (*vault.ExportSecretResponse, error) {
	var metadata []byte

	resp, err := securemem.Run(ctx, func(ctx context.Context, hreq *securemem.HandlerRequest) error {
		data, err := v.cli.KVv1(kvMountPath(req.TenantID)).
			Get(ctx, kvPath(req.ID, req.Version, req.Revision))
		if err != nil {
			return err
		}

		kvData, err := toData(data.Data)
		if err != nil {
			return err
		}

		decodedSecret, err := base64Decode(kvData.Secret)
		if err != nil {
			return err
		}

		// clear the temporary buffer to avoid leaving sensitive data in memory
		defer securemem.Zero(decodedSecret)

		secureSecret, err := hreq.PersistentVault().Reserve(securememImportSecret, len(decodedSecret))
		if err != nil {
			return err
		}

		copy(secureSecret, decodedSecret)

		metadata, err = base64Decode(kvData.Metadata)
		return err
	})

	if err != nil {
		if errors.Is(err, openbao.ErrSecretNotFound) {
			return nil, vault.ErrSecretNotFound
		}
		return nil, err
	}

	data, ok := resp.MemVault().Get(securememImportSecret)
	if !ok {
		err := resp.MemVault().DestroyAll()
		if err != nil {
			return nil, err
		}
		return nil, errAllocatedDataNotFound
	}

	return &vault.ExportSecretResponse{
		Secret:   data,
		Metadata: metadata,
	}, nil
}

// DestroySecret removes the secret from the vault.
func (v *Vault) DestroySecret(ctx context.Context, req vault.DestroySecretRequest) (*vault.DestroySecretResponse, error) {
	err := v.cli.KVv1(kvMountPath(req.TenantID)).
		Delete(ctx, kvPath(req.ID, req.Version, req.Revision))
	if err != nil && !isKVPathDeleted(err) {
		return nil, err
	}
	return &vault.DestroySecretResponse{}, nil
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

func kvPath(id string, version, revision int) string {
	return fmt.Sprintf("%s/%d/%d", id, version, revision)
}

func kvSecretPath(tenantID string) string {
	return tenantID + "/sys/mounts/" + kvSecretName
}

func namespacePath(tenantID string) string {
	return "sys/namespaces/" + tenantID
}
