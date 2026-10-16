// Package staticsecret provides a [cryptor.Sealer] that embeds a fixed AES-256-GCM key,
// removing the need for callers to supply secrets per-request.
package staticsecret

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/securemem"
)

// TypeStaticSecret identifies the static-secret cryptor implementation.
const TypeStaticSecret sealer.Type = "aes256gcm-staticsecret"

// Config holds configuration for the static-secret cryptor.
type Config struct {
	Secret secretprovider.Spec `yaml:"secret"`
}

var _ sealer.SealerConfig = (*Config)(nil)

func (c *Config) ValidateSealerConfig() error {
	return c.Secret.Validate()
}

// StaticSecret is a [cryptor.Sealer] that seals [aes256gcm.AES256GCM] with a pre-configured key,
// so callers don't need to supply secrets per-request.
//
// The caller retains ownership of the secret and must not destroy it while
// StaticSecret is in use.
type StaticSecret struct {
	secret    *securemem.Data
	aes256gcm *aes256gcm.AES256GCM
	name      string
}

// ErrInitializationFailed indicates that New could not be constructed
// due to an unsupported algorithm or invalid key material.
var ErrInitializationFailed = errors.New("static secret initialization failed")

var _ sealer.Sealer = &StaticSecret{}

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
		name:      name,
	}, nil
}

// Seal seals the plaintext using the embedded static key.
func (s *StaticSecret) Seal(ctx context.Context, req sealer.SealRequest) (sealer.SealResponse, error) {
	if req.Plaintext == nil || len(req.Plaintext.SecureBytes()) == 0 {
		return sealer.SealResponse{}, fmt.Errorf("invalid plaintext: %w", cryptor.ErrRequest)
	}

	resp, err := s.aes256gcm.Encrypt(ctx, cryptor.EncryptRequest{
		Secret: cryptor.Secret{
			Data:      s.secret,
			Algorithm: cryptor.KeyAlgorithmAES256,
		},
		Plaintext: req.Plaintext,
		AAD:       req.AAD,
	})
	if err != nil {
		return sealer.SealResponse{}, err
	}

	return sealer.SealResponse{
		Ciphertext: resp.Ciphertext,
	}, nil
}

// Unseal unseals the ciphertext using the embedded static key.
func (s *StaticSecret) Unseal(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
	if req.Ciphertext == nil || len(req.Ciphertext.SecureBytes()) == 0 {
		return sealer.UnsealResponse{}, fmt.Errorf("invalid ciphertext: %w", cryptor.ErrRequest)
	}

	resp, err := s.aes256gcm.Decrypt(ctx, cryptor.DecryptRequest{
		Secret: cryptor.Secret{
			Data:      s.secret,
			Algorithm: cryptor.KeyAlgorithmAES256,
		},
		Ciphertext: req.Ciphertext,
		AAD:        req.AAD,
	})
	if err != nil {
		return sealer.UnsealResponse{}, err
	}

	return sealer.UnsealResponse{
		Plaintext: resp.Plaintext,
	}, nil
}
