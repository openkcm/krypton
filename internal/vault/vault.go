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
	// ErrUnknownType is returned when a vault type is not recognized.
	ErrUnknownType = errors.New("unknown vault type")
	// ErrConfigInvalid is returned when a vault configuration is invalid.
	ErrConfigInvalid = errors.New("invalid vault config")
)

type Config interface {
	ValidateVaultConfig() error
}

// Vault provides secure storage and retrieval of versioned key material.
type Vault interface {
	ImportKey(ctx context.Context, req ImportKeyRequest) (*ImportKeyResponse, error)
	ExportKey(ctx context.Context, req ExportKeyRequest) (*ExportKeyResponse, error)
	DestroyKey(ctx context.Context, req DestroyKeyRequest) (*DestroyKeyResponse, error)
	DestroyKeyVersion(ctx context.Context, req DestroyKeyVersionRequest) (*DestroyKeyVersionResponse, error)
	Info() Info
}

type Type string

// ImportKeyRequest contains parameters for storing key material in the vault.
type ImportKeyRequest struct {
	TenantID    string
	KeyID       string
	KeyVersion  int
	KeyMaterial *securemem.Data
	AAD         []byte
}

// ImportKeyResponse holds the result of an import operation.
type ImportKeyResponse struct {
	// Empty for now, success indicated by nil error
}

// ExportKeyRequest contains parameters for retrieving key material from the vault.
type ExportKeyRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion *int // defaults to latest if nil
}

// ExportKeyResponse holds the retrieved key material and its associated authenticated data.
type ExportKeyResponse struct {
	KeyMaterial *securemem.Data
	AAD         []byte
}

// DestroyKeyRequest contains parameters for destroying all versions of a key.
type DestroyKeyRequest struct {
	TenantID string
	KeyID    string
}

// DestroyKeyResponse holds the list of key versions that were destroyed.
type DestroyKeyResponse struct {
	DestroyedVersions []int
}

// DestroyKeyVersionRequest contains parameters for destroying a specific key version.
type DestroyKeyVersionRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion int
}

// DestroyKeyVersionResponse holds the result of a version destruction operation.
type DestroyKeyVersionResponse struct {
	// Empty for now, success indicated by nil error
}

// Info describes a vault implementation's name and type.
type Info struct {
	Name string
	Type string
}
