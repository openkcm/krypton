package keyprocessor

import (
	"context"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/vault"
	sealergrpc "github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type (
	Processor            = processor
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

func NewProcessor(generator cryptor.SecretGenerator, cryptor cryptor.Cryptor, transportSealer, parent sealer.Sealer, v vault.Vault) *processor {
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

func NewTestRPCManager(client sealergrpc.ServiceClient) *RPCManager {
	return &RPCManager{sealer: client}
}

// NewRootManagerWithVault builds a RootManager from an already-resolved vault,
// letting tests inject a concrete or fault-injecting vault that a
// vaultprovider.Spec cannot express.
func NewRootManagerWithVault(transactor store.Transactor, v vault.Vault, allowed []sealer.Type) *RootManager {
	m := make(map[sealer.Type]struct{}, len(allowed))
	for _, t := range allowed {
		m[t] = struct{}{}
	}
	return &RootManager{transactor: transactor, vault: v, allowed: m}
}
