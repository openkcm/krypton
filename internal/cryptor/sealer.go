package cryptor

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/securemem"
)

type SealRequest struct {
	Plaintext *securemem.Data
	AAD       []byte
}

type SealResponse struct {
	Ciphertext *securemem.Data
}

type UnsealRequest struct {
	Ciphertext *securemem.Data
	AAD        []byte
}

type UnsealResponse struct {
	Plaintext *securemem.Data
}

// Sealer encrypts and decrypts with a self-managed key bound to a trust anchor.
// No external secret is provided; the key material is intrinsic to the implementation.
type Sealer interface {
	Seal(ctx context.Context, req SealRequest) (*SealResponse, error)
	Unseal(ctx context.Context, req UnsealRequest) (*UnsealResponse, error)
	Info() Info
}

// ErrUnexpectedSecret is returned when a RootSealerAdapter receives a non-nil Secret,
// indicating a wiring bug in the processor configuration.
var ErrUnexpectedSecret = errors.New("root sealer adapter received unexpected secret")

// RootSealerAdapter adapts a Sealer to the Cryptor interface for root keys
// that use a non-Krypton trust anchor. This is a special case for root
// processors only, not intended for other positions in the hierarchy.
type RootSealerAdapter struct {
	sealer Sealer
}

func NewRootSealerAdapter(s Sealer) *RootSealerAdapter {
	return &RootSealerAdapter{sealer: s}
}

func (a *RootSealerAdapter) Encrypt(ctx context.Context, req EncryptRequest) (*EncryptResponse, error) {
	if req.Secret != nil {
		return nil, ErrUnexpectedSecret
	}
	resp, err := a.sealer.Seal(ctx, SealRequest{
		Plaintext: req.Plaintext,
		AAD:       req.AAD,
	})
	if err != nil {
		return nil, err
	}
	return &EncryptResponse{Ciphertext: resp.Ciphertext}, nil
}

func (a *RootSealerAdapter) Decrypt(ctx context.Context, req DecryptRequest) (*DecryptResponse, error) {
	if req.Secret != nil {
		return nil, ErrUnexpectedSecret
	}
	resp, err := a.sealer.Unseal(ctx, UnsealRequest{
		Ciphertext: req.Ciphertext,
		AAD:        req.AAD,
	})
	if err != nil {
		return nil, err
	}
	return &DecryptResponse{Plaintext: resp.Plaintext}, nil
}

func (a *RootSealerAdapter) Info() Info {
	return a.sealer.Info()
}
