package keyprocessor

import (
	"context"

	"github.com/openkcm/krypton/internal/securemem"
)

type SecretWrapRequest struct {
	TenantID   string
	KeyID      string
	KeyVersion string
	Secret     *securemem.Data
	AAD        []byte
}

type SecretWrapResponse struct {
	WrappedSecret *securemem.Data
}

type SecretUnwrapRequest struct {
	TenantID      string
	KeyID         string
	KeyVersion    string
	WrappedSecret *securemem.Data
	AAD           []byte
}

type SecretUnwrapResponse struct {
	Secret *securemem.Data
}

// SecretWrapper wraps and unwraps secrets within a key hierarchy.
type SecretWrapper interface {
	WrapSecret(ctx context.Context, req SecretWrapRequest) (*SecretWrapResponse, error)
	UnwrapSecret(ctx context.Context, req SecretUnwrapRequest) (*SecretUnwrapResponse, error)
}
