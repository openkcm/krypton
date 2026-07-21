package keyprocessor

import (
	"context"

	"github.com/openkcm/krypton/internal/securemem"
)

type WrapSecretRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion string
	Secret     *securemem.Data
	AAD        []byte
}

type WrapSecretResponse struct {
	WrappedSecret *securemem.Data
}

type UnwrapSecretRequest struct {
	TenantID      string
	KeyID         string
	KeyVersion    string
	WrappedSecret *securemem.Data
	AAD           []byte
}

type UnwrapSecretResponse struct {
	Secret *securemem.Data
}

// SecretWrapper wraps and unwraps secrets within a key hierarchy.
type SecretWrapper interface {
	WrapSecret(ctx context.Context, req WrapSecretRequest) (*WrapSecretResponse, error)
	UnwrapSecret(ctx context.Context, req UnwrapSecretRequest) (*UnwrapSecretResponse, error)
}
