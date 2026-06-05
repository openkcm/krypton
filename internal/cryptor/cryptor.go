// Package cryptor defines cryptographic interfaces for multi-tenant encrypt/decrypt operations.
// Sensitive data is handled via securemem.Data to prevent leakage into swap or core dumps.
package cryptor

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/securemem"
)

// KeyAlgorithm identifies the encryption algorithm used by a key.
type KeyAlgorithm string

// KeyAlgorithmAES256 represents the AES-256 encryption algorithm.
const KeyAlgorithmAES256 KeyAlgorithm = "AES256"

// InfoName identifies the type of information returned by the Info() method of a Cryptor.
type InfoName string

// CryptorSecret pairs a key algorithm with its key material stored in secure memory.
type CryptorSecret struct {
	// Algorithm is the encryption algorithm to apply.
	Algorithm KeyAlgorithm
	// Data is the raw key bytes in mlock'd memory. Nil if the Cryptor manages its own secrets (e.g., HSM).
	Data *securemem.Data
}

// EncryptRequest contains parameters for an encryption operation.
type EncryptRequest struct {
	// TenantID identifies the tenant owning the key.
	TenantID string
	// KeyID is the unique identifier of the key.
	KeyID string
	// KeyVersion specifies which version of the key to use.
	KeyVersion int
	// Secret holds the key material for encryption. Nil when the Cryptor manages its own secrets.
	Secret *CryptorSecret
	// Plaintext is the data to encrypt.
	// The Plaintext field should not be nil.
	Plaintext *securemem.Data
	// AAD is optional authenticated data bound to the ciphertext without being encrypted.
	AAD []byte
}

// EncryptResponse holds the result of an encryption operation.
type EncryptResponse struct {
	// Ciphertext is the encrypted output.
	Ciphertext *securemem.Data
}

// DecryptRequest contains parameters for a decryption operation.
type DecryptRequest struct {
	// TenantID identifies the tenant owning the key.
	TenantID string
	// KeyID is the unique identifier of the key.
	KeyID string
	// KeyVersion specifies which version of the key to use.
	KeyVersion int
	// Secret holds the key material for decryption. Nil when the Cryptor manages its own secrets.
	Secret *CryptorSecret
	// Ciphertext is the data to decrypt.
	// The Ciphertext field should not be nil.
	Ciphertext *securemem.Data
	// AAD is the authenticated data that must match the value provided at encryption time.
	AAD []byte
}

// DecryptResponse holds the result of a decryption operation.
type DecryptResponse struct {
	// Plaintext is the recovered data.
	Plaintext *securemem.Data
}

// Info describes a Cryptor implementation's capabilities.
type Info struct {
	// Name is a human-readable identifier for the implementation.
	Name InfoName
	// DecryptionSecretRequired is false if cryptor manages its own secret (e.g., HSM).
	DecryptionSecretRequired bool
}

// Encryptor performs encryption.
type Encryptor interface {
	Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResponse, error)
}

// Decryptor performs decryption.
type Decryptor interface {
	Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResponse, error)
}

// Cryptor combines Encryptor and Decryptor with metadata introspection.
type Cryptor interface {
	Encryptor
	Decryptor
	Info() Info
}

var ErrRequest = errors.New("invalid cryptographic request")

func (req EncryptRequest) Validate() error {
	if req.TenantID == "" {
		return fmt.Errorf("invalid tenant ID: %w", ErrRequest)
	}
	if req.KeyID == "" {
		return fmt.Errorf("invalid key ID: %w", ErrRequest)
	}
	if req.KeyVersion == 0 {
		return fmt.Errorf("invalid key version: %w", ErrRequest)
	}
	if req.Plaintext == nil || len(req.Plaintext.SecureBytes()) == 0 {
		return fmt.Errorf("invalid plaintext: %w", ErrRequest)
	}
	return req.Secret.Validate()
}

func (req DecryptRequest) Validate() error {
	if req.TenantID == "" {
		return fmt.Errorf("invalid tenant ID: %w", ErrRequest)
	}
	if req.KeyID == "" {
		return fmt.Errorf("invalid key ID: %w", ErrRequest)
	}
	if req.KeyVersion == 0 {
		return fmt.Errorf("invalid key version: %w", ErrRequest)
	}
	if req.Ciphertext == nil || len(req.Ciphertext.SecureBytes()) == 0 {
		return fmt.Errorf("invalid ciphertext: %w", ErrRequest)
	}
	return req.Secret.Validate()
}

func (cs *CryptorSecret) Validate() error {
	if cs != nil {
		if cs.Algorithm == "" {
			return fmt.Errorf("invalid secret algorithm: %w", ErrRequest)
		}
		if cs.Data == nil || len(cs.Data.SecureBytes()) == 0 {
			return fmt.Errorf("invalid secret data: %w", ErrRequest)
		}
	}
	return nil
}
