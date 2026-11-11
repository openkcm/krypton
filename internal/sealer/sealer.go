package sealer

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/model"
)

// ErrUnknownType is returned when sealer type is unknown.
var ErrUnknownType = errors.New("unknown sealer type")

// Type identifies a sealer implementation for configuration deserialization.
type Type string

// ProviderKeyMetadataKey returns the metadata key for a provider type.
func ProviderKeyMetadataKey(t Type) string {
	return model.ReservedLabelPrefix + string(t) + ":provider-key"
}

// SealRequest identifies a key version and provides the plaintext and AAD to seal.
type SealRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion int
	Plaintext  *securemem.Data
	AAD        []byte
	Metadata   map[string]string
}

// SealResponse holds the sealed ciphertext.
type SealResponse struct {
	Ciphertext *securemem.Data
}

// UnsealRequest identifies a key version and provides the ciphertext and AAD to unseal.
type UnsealRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion int
	Ciphertext *securemem.Data
	AAD        []byte
	Metadata   map[string]string
}

// UnsealResponse holds the unsealed plaintext.
type UnsealResponse struct {
	Plaintext *securemem.Data
}

// Sealer seals and unseals data for a given key version.
type Sealer interface {
	Seal(context.Context, SealRequest) (SealResponse, error)
	Unseal(context.Context, UnsealRequest) (UnsealResponse, error)
}

// SealerConfig is implemented by sealer-specific configuration structs to support validation.
type SealerConfig interface {
	ValidateSealerConfig() error
}

// SealerAuth is implemented by sealer-specific auth/credential structs to support validation.
type SealerAuth interface {
	ValidateSealerAuth() error
}
