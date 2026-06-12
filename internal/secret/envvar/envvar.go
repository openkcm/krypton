// Package envvar provides a secret source that loads key material
// from a base64-encoded environment variable.
package envvar

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/openkcm/krypton/internal/secret"
	"github.com/openkcm/krypton/internal/securemem"
)

// Type identifies the environment variable secret source.
const Type secret.Type = "envvar"

// Config holds configuration for loading a secret from an environment variable.
// The referenced variable must contain the secret as a base64-encoded string (standard encoding).
type Config struct {
	Name string `yaml:"name"` // environment variable name
}

var _ secret.Config = (*Config)(nil)

// ValidateSecretConfig checks that the environment variable name is set.
func (c *Config) ValidateSecretConfig() error {
	if c.Name == "" {
		return errors.New("environment variable name must not be empty")
	}
	return nil
}

var (
	ErrEnvVarEmpty  = errors.New("environment variable is empty or not set")
	ErrBase64Decode = errors.New("failed to base64-decode secret")
	ErrSecureMemory = errors.New("secure memory error")
)

// Loader loads secret key material from a base64-encoded environment variable.
type Loader struct {
	cfg *Config
}

var _ secret.Loader = (*Loader)(nil)

// New creates a Loader bound to the given config.
func New(cfg *Config) *Loader {
	return &Loader{cfg: cfg}
}

const memKey = "envvar-secret"

// LoadSecret reads and base64-decodes the secret from the configured environment variable.
func (l *Loader) LoadSecret(ctx context.Context) (*securemem.Data, error) {
	raw := os.Getenv(l.cfg.Name)
	if raw == "" {
		return nil, fmt.Errorf("%w: %s", ErrEnvVarEmpty, l.cfg.Name)
	}

	resp, err := securemem.Run(ctx, func(_ context.Context, req *securemem.HandlerRequest) error {
		keyBytes, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrBase64Decode, err)
		}

		b, err := req.PersistentVault().Reserve(memKey, len(keyBytes))
		if err != nil {
			return err
		}
		copy(b, keyBytes)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecureMemory, err)
	}

	secdata, ok := resp.MemVault().Get(memKey)
	if !ok {
		destroyErr := resp.MemVault().DestroyAll()
		return nil, errors.Join(
			fmt.Errorf("%w: could not retrieve key from vault", ErrSecureMemory),
			destroyErr,
		)
	}

	return secdata, nil
}
