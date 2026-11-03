// Package inline provides a secret source that carries base64-encoded key
// material inline, for secrets supplied directly (e.g. over the admin API)
// rather than referenced from an external source.
package inline

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/secret"
	"github.com/openkcm/krypton/internal/securemem"
)

// Type identifies the inline secret source.
const Type secret.Type = "inline"

var (
	ErrSecretEmpty  = errors.New("inline secret is empty")
	ErrBase64Decode = errors.New("failed to base64-decode secret")
	ErrKeySize      = errors.New("inline secret has invalid key size")
	ErrSecureMemory = errors.New("secure memory error")
)

// Config holds base64-encoded (standard encoding) key material inline.
type Config struct {
	Secret string `yaml:"secret"`
}

var _ secret.Config = (*Config)(nil)

// ValidateSecretConfig checks that the secret is set, decodes, and is a valid
// AES-256 key size.
func (c *Config) ValidateSecretConfig() error {
	if c.Secret == "" {
		return ErrSecretEmpty
	}
	b, err := base64.StdEncoding.DecodeString(c.Secret)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBase64Decode, err)
	}
	defer securemem.Zero(b)
	if len(b) != aes256gcm.KeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrKeySize, aes256gcm.KeySize, len(b))
	}
	return nil
}

// Loader loads key material from a base64-encoded inline secret.
type Loader struct {
	cfg *Config
}

var _ secret.Loader = (*Loader)(nil)

// New creates a Loader bound to the given config.
func New(cfg *Config) *Loader {
	return &Loader{cfg: cfg}
}

const memKey = "inline-secret"

// LoadSecret base64-decodes the inline secret into secure memory.
func (l *Loader) LoadSecret(ctx context.Context) (*securemem.Data, error) {
	if l.cfg.Secret == "" {
		return nil, ErrSecretEmpty
	}

	resp, err := securemem.Run(ctx, func(_ context.Context, req *securemem.HandlerRequest) error {
		keyBytes, err := base64.StdEncoding.DecodeString(l.cfg.Secret)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrBase64Decode, err)
		}
		defer securemem.Zero(keyBytes)

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
