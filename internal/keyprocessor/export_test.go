package keyprocessor

import (
	"context"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

func NewProcessor(generator cryptor.SecretGenerator, wrapper, transportSealer, parent cryptor.Cryptor, v vault.Vault) *Processor {
	return &Processor{
		generator:       generator,
		wrapper:         wrapper,
		transportSealer: transportSealer,
		parent:          parent,
		vault:           v,
	}
}

func NewManager(s store.Key, kvs store.KeyVersion, processors map[model.KeyKind]Processor) *Manager {
	return &Manager{store: s, keyVersionStore: kvs, processors: processors}
}

func (p *Processor) ResolveSecret(ctx context.Context, kv model.KeyVersion) (*securemem.Data, error) {
	return p.resolveSecret(ctx, kv)
}
