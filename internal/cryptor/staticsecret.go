package cryptor

import (
	"context"
	"fmt"

	"github.com/openkcm/krypton/internal/securemem"
)

// StaticSecret is a [Cryptor] that wraps [AES256GCM] with a pre-configured key,
// so callers don't need to supply secrets per-request. It rejects requests that
// include a secret, and injects its own before delegating to the underlying cipher.
//
// The caller retains ownership of the secret and must not destroy it while
// StaticSecret is in use.
type StaticSecret struct {
	secret    *securemem.Data
	aes256gcm *AES256GCM
	info      Info
}

var _ Cryptor = &StaticSecret{}

// NewStaticSecret returns a StaticSecret for the given algorithm name and key material.
// Currently only [InfoNameStaticSecret] is supported. The secret must be non-nil and non-empty.
func NewStaticSecret(name InfoName, secret *securemem.Data) (*StaticSecret, error) {
	if name != InfoNameStaticSecret {
		return nil, ErrRequest
	}

	if secret == nil || len(secret.SecureBytes()) == 0 {
		return nil, ErrRequest
	}

	return &StaticSecret{
		secret:    secret,
		aes256gcm: NewAES256GCM(),
		info: Info{
			Name:                     name,
			DecryptionSecretRequired: false,
		},
	}, nil
}

// Decrypt implements [Cryptor]. It returns an error if the request contains a secret.
func (s *StaticSecret) Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResponse, error) {
	err := req.Validate()
	if err != nil {
		return nil, err
	}
	if req.Secret != nil {
		return nil, fmt.Errorf("decryption secret should not be provided in the request: %w", ErrRequest)
	}
	// replacing the secret in the request with the static secret
	req.Secret = s.secret

	switch req.Algorithm {
	case KeyAlgorithmAES256:
		return s.aes256gcm.Decrypt(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported decryption algorithm: %s: %w", req.Algorithm, ErrRequest)
	}
}

// Encrypt implements [Cryptor]. It returns an error if the request contains a secret.
func (s *StaticSecret) Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResponse, error) {
	err := req.Validate()
	if err != nil {
		return nil, err
	}
	if req.Secret != nil {
		return nil, fmt.Errorf("encryption secret should not be provided in the request: %w", ErrRequest)
	}
	// replacing the secret in the request with the static secret
	req.Secret = s.secret

	switch req.Algorithm {
	case KeyAlgorithmAES256:
		return s.aes256gcm.Encrypt(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s: %w", req.Algorithm, ErrRequest)
	}
}

// Info implements [Cryptor].
func (s *StaticSecret) Info() Info {
	return s.info
}
