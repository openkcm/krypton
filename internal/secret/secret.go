// Package secret defines interfaces for loading cryptographic key material
// from external sources (environment variables, files, vaults, etc.).
package secret

import (
	"context"

	"github.com/openkcm/krypton/internal/securemem"
)

// Type identifies a secret source implementation for configuration deserialization.
type Type string

// Config is implemented by each secret source's configuration struct.
type Config interface {
	ValidateSecretConfig() error
}

// Loader loads secret key material from an external source.
type Loader interface {
	LoadSecret(ctx context.Context) (*securemem.Data, error)
}
