package cryptor

import (
	"context"

	"github.com/openkcm/krypton/internal/securemem"
)

// SealRequest identifies a key version and provides the plaintext and AAD to seal.
type SealRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion string
	Plaintext  *securemem.Data
	AAD        []byte
}

// SealResponse holds the sealed ciphertext.
type SealResponse struct {
	Ciphertext *securemem.Data
}

// UnsealRequest identifies a key version and provides the ciphertext and AAD to unseal.
type UnsealRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion string
	Ciphertext *securemem.Data
	AAD        []byte
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
