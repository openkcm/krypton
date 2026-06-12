// Package staticsecret provides a [cryptor.Cryptor] that embeds a fixed AES-256-GCM key,
// removing the need for callers to supply secrets per-request.
package staticsecret

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/securemem"
)

// TypeStaticSecret identifies the static-secret cryptor implementation.
const TypeStaticSecret cryptor.Type = "aes256gcm-staticsecret"

// Config holds configuration for the static-secret cryptor.
type Config struct {
	Secret secretprovider.Spec `yaml:"secret"`
}

var _ cryptor.Config = (*Config)(nil)

func (c *Config) ValidateCryptorConfig() error {
	return c.Secret.Validate()
}

// StaticSecret is a [Cryptor] that wraps [AES256GCM] with a pre-configured key,
// so callers don't need to supply secrets per-request. It rejects requests that
// include a secret, and injects its own before delegating to the underlying cipher.
//
// The caller retains ownership of the secret and must not destroy it while
// StaticSecret is in use.
type StaticSecret struct {
	secret    *securemem.Data
	aes256gcm *aes256gcm.AES256GCM
	info      cryptor.Info
}

// ErrInitializationFailed indicates that New could not be constructed
// due to an unsupported algorithm or invalid key material.
var ErrInitializationFailed = errors.New("static secret initialization failed")

var _ cryptor.Cryptor = &StaticSecret{}

// New returns a StaticSecret with the given instance name and key material.
// The secret must be non-nil and exactly 32 bytes (AES-256).
func New(name string, secret *securemem.Data) (*StaticSecret, error) {
	if name == "" {
		return nil, fmt.Errorf("name must not be empty: %w", ErrInitializationFailed)
	}

	if secret == nil || len(secret.SecureBytes()) != aes256gcm.KeySize {
		return nil, fmt.Errorf("invalid secret: %w", ErrInitializationFailed)
	}

	return &StaticSecret{
		secret:    secret,
		aes256gcm: aes256gcm.New(name),
		info: cryptor.Info{
			Name:                     name,
			Type:                     TypeStaticSecret,
			DecryptionSecretRequired: false,
		},
	}, nil
}

// Decrypt implements [Cryptor]. It returns an error if the request contains a secret.
func (s *StaticSecret) Decrypt(ctx context.Context, req cryptor.DecryptRequest) (*cryptor.DecryptResponse, error) {
	err := req.Validate()
	if err != nil {
		return nil, err
	}

	if req.Secret != nil {
		return nil, fmt.Errorf("decryption secret should not be provided in the request: %w", cryptor.ErrRequest)
	}
	// replacing the secret in the request with the static secret
	req.Secret = &cryptor.Secret{
		Data:      s.secret,
		Algorithm: cryptor.KeyAlgorithmAES256,
	}

	return s.aes256gcm.Decrypt(ctx, req)
}

// Encrypt implements [Cryptor]. It returns an error if the request contains a secret.
func (s *StaticSecret) Encrypt(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
	err := req.Validate()
	if err != nil {
		return nil, err
	}

	if req.Secret != nil {
		return nil, fmt.Errorf("encryption secret should not be provided in the request: %w", cryptor.ErrRequest)
	}
	// replacing the secret in the request with the static secret
	req.Secret = &cryptor.Secret{
		Data:      s.secret,
		Algorithm: cryptor.KeyAlgorithmAES256,
	}

	return s.aes256gcm.Encrypt(ctx, req)
}

// Info implements [Cryptor].
func (s *StaticSecret) Info() cryptor.Info {
	return s.info
}
