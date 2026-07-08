package keyprocessor

import (
	"context"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/pkg/model"
)

func NewProcessor(generator cryptor.SecretGenerator, wrapper, sealer cryptor.Cryptor, v vault.Vault, parent *Processor) *Processor {
	return &Processor{
		generator: generator,
		wrapper:   wrapper,
		sealer:    sealer,
		vault:     v,
		parent:    parent,
	}
}

func (p *Processor) ResolveSecret(ctx context.Context, keyChain []model.Key) (*securemem.Data, error) {
	return p.resolveSecret(ctx, keyChain)
}
