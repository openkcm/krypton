package vault

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/securemem"
)

var (
	// ErrSecretNotFound is returned when a secret does not exist.
	ErrSecretNotFound = errors.New("secret not found")
	// ErrInvalidRequest is returned when a request contains invalid or missing parameters.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrUnknownType is returned when the vault type is not recognized.
	ErrUnknownType = errors.New("unknown vault type")
)

// Vault stores secrets.
//
// A secret is identified by tenant and ID, optionally qualified by version and
// revision. A revision always belongs to a version.
type Vault interface {
	PrepareTenant(ctx context.Context, req PrepareTenantRequest) (*PrepareTenantResponse, error)
	ImportSecret(ctx context.Context, req ImportSecretRequest) (*ImportSecretResponse, error)
	ExportSecret(ctx context.Context, req ExportSecretRequest) (*ExportSecretResponse, error)
	DestroySecret(ctx context.Context, req DestroySecretRequest) (*DestroySecretResponse, error)
	DestroyTenant(ctx context.Context, req DestroyTenantRequest) (*DestroyTenantResponse, error)
	Info() Info
}

// Config is implemented by vault-specific configuration structs to support validation.
type Config interface {
	ValidateVaultConfig() error
}

// Type identifies a vault implementation for configuration deserialization.
type Type string

// PrepareTenantRequest contains parameters for preparing a tenant in the vault.
type PrepareTenantRequest struct {
	TenantID string
	Name     string
}

// PrepareTenantResponse holds the result of a tenant preparation operation.
type PrepareTenantResponse struct {
}

// ImportSecretRequest contains parameters for storing a secret and its metadata in the vault.
type ImportSecretRequest struct {
	TenantID string
	ID       string
	Version  int
	Revision int
	Secret   *securemem.Data
	Metadata []byte
}

// ImportSecretResponse holds the result of an import operation.
type ImportSecretResponse struct {
	// Empty for now, success indicated by nil error
}

// ExportSecretRequest contains parameters for retrieving a secret from the vault.
type ExportSecretRequest struct {
	TenantID string
	ID       string
	Version  int
	Revision int
}

// ExportSecretResponse holds the retrieved secret and its metadata.
type ExportSecretResponse struct {
	Secret   *securemem.Data
	Metadata []byte
}

// DestroySecretRequest contains parameters for destroying a secret.
type DestroySecretRequest struct {
	TenantID string
	ID       string
	Version  int
	Revision int
}

// DestroySecretResponse holds the result of a destruction operation.
type DestroySecretResponse struct {
	// Empty for now, success indicated by nil error
}

// Info describes a vault implementation's name and type.
type Info struct {
	Name string
	Type Type
}

// DestroyTenantRequest contains parameters for removing a tenant from the vault.
type DestroyTenantRequest struct {
	TenantID string
}

// DestroyTenantResponse holds the result of a tenant destruction operation.
type DestroyTenantResponse struct {
	// Empty for now, success indicated by nil error
}
