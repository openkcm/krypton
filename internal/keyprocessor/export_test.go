package keyprocessor

import (
	"context"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/pkg/model"
)

func NewProcessor(name string, v vault.Vault, c cryptor.Cryptor, sg cryptor.SecretGenerator, internal *Processor, parent *Processor) *Processor {
	return &Processor{
		name:            name,
		vault:           v,
		cryptor:         c,
		secretGenerator: sg,
		internal:        internal,
		parent:          parent,
	}
}

func (p *Processor) ResolveSecret(ctx context.Context, keyChain []model.Key) (*securemem.Data, error) {
	return p.resolveSecret(ctx, keyChain)
}
