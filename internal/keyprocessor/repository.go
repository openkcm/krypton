package keyprocessor

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/pkg/model"
)

var (
	ErrEmptyBindings            = errors.New("bindings cannot be empty")
	ErrKindMissing              = errors.New("key kind not found")
	ErrMissingParentKeyProvider = errors.New("non-root key has no parent processor or parent agent")
)

type Repository struct {
	processors map[model.KeyKind]*KeyProcessor
}

func NewRepository(ctx context.Context, hierarchy spec.KeyHierarchy, bindings map[string]spec.KeyBinding) (*Repository, error) {
	if len(bindings) == 0 {
		return nil, ErrEmptyBindings
	}

	processors := make(map[model.KeyKind]*KeyProcessor, len(bindings))

	for kindStr, binding := range bindings {
		kind := model.KeyKind(kindStr)
		keySpec, ok := hierarchy.FindKeySpec(kind)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrKindMissing, kind)
		}

		var v vault.Vault
		if binding.Vault != nil {
			var err error
			v, err = binding.Vault.Open(ctx)
			if err != nil {
				return nil, fmt.Errorf("kind %q: open vault: %w", kind, err)
			}
		}

		bundle, err := binding.Cryptor.Open(ctx)
		if err != nil {
			return nil, fmt.Errorf("kind %q: open cryptor: %w", kind, err)
		}

		processors[kind] = &KeyProcessor{
			keySpec:         keySpec,
			cryptor:         bundle.Cryptor,
			secretGenerator: bundle.SecretGenerator,
			vault:           v,
		}
	}

	for i, ks := range hierarchy.KeySpecs {
		proc, ok := processors[ks.Kind]
		if !ok || i == 0 {
			continue
		}
		kind := hierarchy.KeySpecs[i-1].Kind
		parent, found := processors[kind]
		if !found {
			return nil, fmt.Errorf("kind %q: %w", kind, ErrMissingParentKeyProvider)
		}
		proc.parent = parent
	}

	return &Repository{processors: processors}, nil
}

func (r *Repository) GetProcessorByKind(kind model.KeyKind) (*KeyProcessor, error) {
	p, ok := r.processors[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrKindMissing, kind)
	}
	return p, nil
}
