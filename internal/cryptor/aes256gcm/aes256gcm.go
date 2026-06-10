// Package aes256gcm provides an AES-256-GCM [cryptor.Cryptor] implementation.
// All sensitive data is handled in mlock'd memory via securemem.
package aes256gcm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
)

const (
	// plainTextKey is the vault key used to store decrypted plaintext in secure memory.
	plainTextKey = "plainText"
	// cipherTextKey is the vault key used to store encrypted ciphertext in secure memory.
	cipherTextKey = "cipherText"
)

const TypeAES256GCM cryptor.Type = "aes256gcm"

// CryptorConfig is the configuration for an AES-256-GCM cryptor.
type CryptorConfig struct{}

var _ cryptor.Config = (*CryptorConfig)(nil)

func (c *CryptorConfig) ValidateCryptorConfig() error {
	// TODO: validate
	return nil
}

// AES256GCM implements the Cryptor interface using AES-256 in Galois/Counter Mode.
// All key material and intermediate plaintext/ciphertext are handled in mlock'd
// memory via securemem to prevent leakage into swap or core dumps.
type AES256GCM struct {
	info cryptor.Info
}

var _ cryptor.Cryptor = &AES256GCM{}

// InfoNameAES256GCM indicates that the Cryptor supports AES-256 in Galois/Counter Mode (GCM).
const InfoNameAES256GCM cryptor.InfoName = "AES256-GCM"

// ErrAllocatedDataNotFound indicates that data reserved in the secure memory vault
// could not be retrieved after the cryptographic operation completed.
var ErrAllocatedDataNotFound = errors.New("allocated data not found in vault")

// New returns a ready-to-use AES-256-GCM cryptor.
func New() *AES256GCM {
	return &AES256GCM{
		info: cryptor.Info{
			Name:                     InfoNameAES256GCM,
			DecryptionSecretRequired: true,
		},
	}
}

// Info returns metadata about the AES256GCM cryptor.
func (a *AES256GCM) Info() cryptor.Info {
	return a.info
}

// Encrypt encrypts the plaintext using AES-256 in GCM mode with the provided key and AAD.
func (a *AES256GCM) Encrypt(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	if req.Secret == nil {
		return nil, fmt.Errorf("missing encryption secret: %w", cryptor.ErrRequest)
	}

	if req.Secret.Algorithm != cryptor.KeyAlgorithmAES256 {
		return nil, fmt.Errorf("invalid key algorithm: expected %s, got %s: %w", cryptor.KeyAlgorithmAES256, req.Secret.Algorithm, cryptor.ErrRequest)
	}

	secretSize := len(req.Secret.Data.SecureBytes())
	if secretSize != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d: %w", secretSize, cryptor.ErrRequest)
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, hr *securemem.HandlerRequest) error {
		// 1. Initialize AES-256 block cipher from the 32-byte key.
		block, err := aes.NewCipher(req.Secret.Data.SecureBytes())
		if err != nil {
			return fmt.Errorf("failed to create AES cipher: %w", err)
		}

		// 2. Wrap the block cipher in GCM mode for authenticated encryption.
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("failed to create GCM: %w", err)
		}

		// 3. Compute total output size: nonce + ciphertext + auth tag.
		nonceSize := gcm.NonceSize()
		totalSealDataSize := nonceSize + len(req.Plaintext.SecureBytes()) + gcm.Overhead()

		// 4. Reserve secure (mlock'd) memory in the persistent vault for the output.
		cipherBytes, err := hr.PersistentVault().Reserve(cipherTextKey, totalSealDataSize)
		if err != nil {
			return fmt.Errorf("failed to allocate secure memory for ciphertext: %w", err)
		}

		// 5. Generate a random nonce and write it to the front of the output buffer.
		nonce := cipherBytes[:nonceSize]
		if _, err := rand.Read(nonce); err != nil {
			return fmt.Errorf("failed to generate nonce: %w", err)
		}

		// 6. Seal plaintext into the buffer after the nonce.
		//    Output layout: [nonce || ciphertext || tag]
		gcm.Seal(cipherBytes[nonceSize:nonceSize], nonce, req.Plaintext.SecureBytes(), req.AAD)

		return nil
	})
	if err != nil {
		return nil, err
	}

	// 7. Retrieve the sealed ciphertext from the (now read-only) vault.
	cipherText, ok := resp.MemVault().Get(cipherTextKey)
	if !ok {
		// This should never happen since we just reserved this memory, but if it does, destroy all vault data to be safe.
		err = resp.MemVault().DestroyAll()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("allocated ciphertext not found in vault after encryption: %w", ErrAllocatedDataNotFound)
	}

	return &cryptor.EncryptResponse{
		Ciphertext: cipherText,
	}, nil
}

// Decrypt decrypts the ciphertext using AES-256 in GCM mode with the provided key and AAD.
func (a *AES256GCM) Decrypt(ctx context.Context, req cryptor.DecryptRequest) (*cryptor.DecryptResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}

	if req.Secret == nil {
		return nil, fmt.Errorf("missing decryption secret: %w", cryptor.ErrRequest)
	}

	if req.Secret.Algorithm != cryptor.KeyAlgorithmAES256 {
		return nil, fmt.Errorf("invalid key algorithm: expected %s, got %s: %w", cryptor.KeyAlgorithmAES256, req.Secret.Algorithm, cryptor.ErrRequest)
	}

	secretSize := len(req.Secret.Data.SecureBytes())
	if secretSize != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d: %w", secretSize, cryptor.ErrRequest)
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, hr *securemem.HandlerRequest) error {
		// 1. Initialize AES-256 block cipher from the 32-byte key.
		block, err := aes.NewCipher(req.Secret.Data.SecureBytes())
		if err != nil {
			return fmt.Errorf("failed to create AES cipher: %w", err)
		}

		// 2. Wrap the block cipher in GCM mode for authenticated decryption.
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return fmt.Errorf("failed to create GCM: %w", err)
		}

		nonceSize := gcm.NonceSize()
		cipherTextSize := len(req.Ciphertext.SecureBytes())

		// 3. Verify the ciphertext is at least nonce + tag bytes long.
		if cipherTextSize < nonceSize+gcm.Overhead() {
			return fmt.Errorf("ciphertext too short: %w", cryptor.ErrRequest)
		}

		// 4. Compute plaintext size: total - nonce - tag.
		plainTextSize := cipherTextSize - nonceSize - gcm.Overhead()

		// 5. Reserve secure (mlock'd) memory in the persistent vault for the plaintext.
		plainBytes, err := hr.PersistentVault().Reserve(plainTextKey, plainTextSize)
		if err != nil {
			return fmt.Errorf("failed to allocate secure memory for plaintext: %w", err)
		}

		// 6. Decrypt and authenticate. Open appends the plaintext into plainBytes'
		//    backing array (passed as [:0] so it writes from the start).
		//    Input layout: [nonce || ciphertext || tag]
		nonce := req.Ciphertext.SecureBytes()[:nonceSize]
		ciphertext := req.Ciphertext.SecureBytes()[nonceSize:]

		_, err = gcm.Open(
			plainBytes[:0],
			nonce,
			ciphertext,
			req.AAD,
		)
		if err != nil {
			return fmt.Errorf("failed to decrypt: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// 7. Retrieve the decrypted plaintext from the (now read-only) vault.
	plainText, ok := resp.MemVault().Get(plainTextKey)
	if !ok {
		// This should never happen since we just reserved this memory, but if it does, destroy all vault data to be safe.
		err = resp.MemVault().DestroyAll()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("allocated plaintext not found in vault after decryption: %w", ErrAllocatedDataNotFound)
	}

	return &cryptor.DecryptResponse{
		Plaintext: plainText,
	}, nil
}
