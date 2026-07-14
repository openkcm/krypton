package keyprocessor

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// ErrProcessorNotFound is returned when no processor is registered for a key's kind.
var ErrProcessorNotFound = errors.New("key processor could not be found")

// TypeManager identifies the Manager cryptor type.
const TypeManager cryptor.Type = "manager"

// Manager encrypts and decrypts secrets by looking up the key and delegating
// to the Processor registered for that key's kind.
type Manager struct {
	store      store.Key
	processors map[model.KeyKind]Processor
}

var _ cryptor.Cryptor = &Manager{}

// Encrypt looks up the key and delegates to the matching processor.
func (km *Manager) Encrypt(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
	key, err := km.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return nil, err
	}
	proc, ok := km.processors[key.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: key kind %s", ErrProcessorNotFound, key.Kind)
	}

	resp, err := proc.WrapSecret(ctx, WrapSecretRequest{
		Key:    *key,
		Secret: req.Plaintext,
		AAD:    req.AAD,
	})
	if err != nil {
		return nil, err
	}

	return &cryptor.EncryptResponse{
		Ciphertext: resp.WrappedSecret,
	}, nil
}

// Decrypt looks up the key and delegates to the matching processor.
func (km *Manager) Decrypt(ctx context.Context, req cryptor.DecryptRequest) (*cryptor.DecryptResponse, error) {
	key, err := km.store.GetKeyByID(ctx, req.KeyID, req.TenantID)
	if err != nil {
		return nil, err
	}
	proc, ok := km.processors[key.Kind]
	if !ok {
		return nil, fmt.Errorf("%w: key kind %s", ErrProcessorNotFound, key.Kind)
	}

	resp, err := proc.UnwrapSecret(ctx, UnwrapSecretRequest{
		Key:           *key,
		WrappedSecret: req.Ciphertext,
		AAD:           req.AAD,
	})
	if err != nil {
		return nil, err
	}

	return &cryptor.DecryptResponse{
		Plaintext: resp.Secret,
	}, nil
}

// Info returns the Manager's cryptor metadata.
func (km *Manager) Info() cryptor.Info {
	return cryptor.Info{
		Name:                     "keyprocessor-manager",
		Type:                     TypeManager,
		DecryptionSecretRequired: true,
	}
}
