package vault

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/securemem"
)

var (
	// ErrKeyNotFound is returned when a key or key version does not exist in the vault.
	ErrKeyNotFound = errors.New("key not found")
	// ErrInvalidRequest is returned when a request contains invalid or missing parameters.
	ErrInvalidRequest = errors.New("invalid request")
	// ErrUnknownType is returned when the vault type is not recognized.
	ErrUnknownType = errors.New("unknown vault type")
)

// Vault provides secure storage and retrieval of versioned key material.
type Vault interface {
	PrepareTenant(ctx context.Context, req PrepareTenantRequest) (*PrepareTenantResponse, error)
	ImportKey(ctx context.Context, req ImportKeyRequest) (*ImportKeyResponse, error)
	ExportKey(ctx context.Context, req ExportKeyRequest) (*ExportKeyResponse, error)
	DestroyKey(ctx context.Context, req DestroyKeyRequest) (*DestroyKeyResponse, error)
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

// ImportKeyRequest contains parameters for storing key material in the vault.
type ImportKeyRequest struct {
	TenantID    string
	KeyID       string
	KeyVersion  int
	KeyRevision int
	KeyMaterial *securemem.Data
	AAD         []byte
}

// ImportKeyResponse holds the result of an import operation.
type ImportKeyResponse struct {
	// Empty for now, success indicated by nil error
}

// ExportKeyRequest contains parameters for retrieving key material from the vault.
type ExportKeyRequest struct {
	TenantID    string
	KeyID       string
	KeyVersion  int
	KeyRevision int
}

// ExportKeyResponse holds the retrieved key material and its associated authenticated data.
type ExportKeyResponse struct {
	KeyMaterial *securemem.Data
	AAD         []byte
}

// DestroyKeyRequest contains parameters for destroying a specific key version.
type DestroyKeyRequest struct {
	TenantID    string
	KeyID       string
	KeyVersion  int
	KeyRevision int
}

// DestroyKeyResponse holds the result of a version destruction operation.
type DestroyKeyResponse struct {
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
