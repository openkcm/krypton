package cryptor

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/securemem"
)

// GenerateSecretRequest specifies the algorithm and logical name for a new secret key.
type GenerateSecretRequest struct {
	Algorithm KeyAlgorithm
	Name      string
}

// GenerateSecretResponse holds the generated secret stored in secure (mlock'd) memory.
// The caller is responsible for calling Secret.Destroy() when the key is no longer needed.
type GenerateSecretResponse struct {
	Secret *securemem.Data
}

// SecretGenerator generates cryptographic secret keys into secure memory.
type SecretGenerator interface {
	GenerateSecret(ctx context.Context, req GenerateSecretRequest) (*GenerateSecretResponse, error)
}

// ErrSecretGenRequest indicates that the secret generation request is invalid,
// such as unsupported algorithm or missing name.
var ErrSecretGenRequest = errors.New("invalid secret generation request")

// ErrAllocatedSecretNotFound indicates that the secret key generated and allocated in the vault cannot be found.
var ErrAllocatedSecretNotFound = errors.New("allocated secret not found in vault")

// AES256SecretGenerator generates 256-bit AES keys using crypto/rand.
// The generated key material is stored in mlock'd memory and never touches the Go heap.
type AES256SecretGenerator struct{}

var _ SecretGenerator = &AES256SecretGenerator{}

// NewAES256SecretGenerator returns a ready-to-use secret generator.
func NewAES256SecretGenerator() *AES256SecretGenerator {
	return &AES256SecretGenerator{}
}

// GenerateSecret generates a new AES-256 secret key and stores it in mlock'd memory.
// Returns ErrSecretGenRequest if Algorithm is not KeyAlgorithmAES256 or Name is empty.
// The caller must call resp.Secret.Destroy() when the key is no longer needed.
func (a *AES256SecretGenerator) GenerateSecret(ctx context.Context, req GenerateSecretRequest) (*GenerateSecretResponse, error) {
	if req.Algorithm != KeyAlgorithmAES256 {
		return nil, fmt.Errorf("unsupported key algorithm: %w", ErrSecretGenRequest)
	}

	if req.Name == "" {
		return nil, fmt.Errorf("name is empty: %w", ErrSecretGenRequest)
	}

	resp, err := securemem.Run(ctx, func(ctx context.Context, hReq *securemem.HandlerRequest) error {
		b, err := hReq.PersistentVault().Reserve(req.Name, 32)
		if err != nil {
			return fmt.Errorf("failed to allocate new securemem bytes: %w", err)
		}

		_, err = rand.Read(b)
		if err != nil {
			return fmt.Errorf("failed to generate random bytes: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	secret, ok := resp.MemVault().Get(req.Name)
	if !ok {
		// This should never happen since we just reserved this memory, but if it does, destroy all vault data to be safe.
		err = resp.MemVault().DestroyAll()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("allocated secret not found in vault after generation: %w", ErrAllocatedSecretNotFound)
	}

	return &GenerateSecretResponse{
		Secret: secret,
	}, nil
}
