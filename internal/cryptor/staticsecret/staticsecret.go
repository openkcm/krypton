// Package staticsecret provides a [cryptor.Cryptor] that embeds a fixed AES-256-GCM key,
// removing the need for callers to supply secrets per-request.
package staticsecret

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/securemem"
)

const TypeHSM cryptor.Type = "hsm"

// CryptorConfig is the configuration for the static-secret (HSM-simulated) cryptor.
type CryptorConfig struct{}

var _ cryptor.Config = (*CryptorConfig)(nil)

func (c *CryptorConfig) ValidateCryptorConfig() error {
	// TODO: validate
	return nil
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

// InfoNameStaticSecret indicates a Cryptor that manages its own static key material.
const InfoNameStaticSecret cryptor.InfoName = "AES256-GCM-STATIC-SECRET"

// New returns a StaticSecret for the given algorithm name and key material.
// Currently only [InfoNameStaticSecret] is supported. The secret must be non-nil and non-empty.
func New(name cryptor.InfoName, secret *securemem.Data) (*StaticSecret, error) {
	if name != InfoNameStaticSecret {
		return nil, fmt.Errorf("unsupported algorithm name: %s: %w", name, ErrInitializationFailed)
	}

	if secret == nil || len(secret.SecureBytes()) != 32 {
		return nil, fmt.Errorf("invalid secret: %w", ErrInitializationFailed)
	}

	return &StaticSecret{
		secret:    secret,
		aes256gcm: aes256gcm.New(),
		info: cryptor.Info{
			Name:                     name,
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
