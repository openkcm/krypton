package keyprocessor

import (
	"context"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type (
	Processor            = processor
	RootManager          = rootManager
	CreateSecretRequest  = createSecretRequest
	CreateSecretResponse = createSecretResponse
	DeleteSecretRequest  = deleteSecretRequest
	DeleteSecretResponse = deleteSecretResponse
)

func (p *processor) CreateSecret(ctx context.Context, req createSecretRequest) (createSecretResponse, error) {
	return p.createSecret(ctx, req)
}

func (p *processor) DeleteSecret(ctx context.Context, req deleteSecretRequest) (deleteSecretResponse, error) {
	return p.deleteSecret(ctx, req)
}

func (p *processor) ResolveSecret(ctx context.Context, kv model.KeyVersion) (cryptor.Secret, error) {
	return p.resolveSecret(ctx, kv)
}

func (p *processor) Encrypt(ctx context.Context, req cryptor.EncryptRequest) (*cryptor.EncryptResponse, error) {
	return p.encrypt(ctx, req)
}

func (p *processor) Decrypt(ctx context.Context, req cryptor.DecryptRequest) (*cryptor.DecryptResponse, error) {
	return p.decrypt(ctx, req)
}

func NewProcessor(generator cryptor.SecretGenerator, cryptor cryptor.Cryptor, transportSealer, parent cryptor.Sealer, v vault.Vault) *processor {
	return &processor{
		generator:       generator,
		cryptor:         cryptor,
		transportSealer: transportSealer,
		parent:          parent,
		vault:           v,
	}
}

func NewTestManager(s store.Key, kvs store.KeyVersion, processors map[model.KeyKind]processor) *Manager {
	return &Manager{store: s, versionStore: kvs, processors: processors}
}

func NewTestManagerWithAlgorithms(s store.Key, kvs store.KeyVersion, processors map[model.KeyKind]processor, algorithms map[model.KeyKind]cryptor.KeyAlgorithm) *Manager {
	return &Manager{store: s, versionStore: kvs, processors: processors, algorithms: algorithms}
}

func NewTestRootManager(s store.Key, sealer cryptor.Sealer) *rootManager {
	return &rootManager{store: s, sealer: sealer}
}
