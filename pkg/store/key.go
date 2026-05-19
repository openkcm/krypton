package store

import (
	"context"
	"errors"
	"iter"
	"slices"

	"github.com/openkcm/krypton/pkg/model"
)

var ErrKeyNotFound = errors.New("key not found")

type Key interface {
	CreateKey(ctx context.Context, key model.Key) error
	GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error)
	GetKeyChain(ctx context.Context, query GetKeyChainQuery) (GetKeyChainResult, error)
	GetKeyTree(ctx context.Context, query GetKeyTreeQuery) (GetKeyTreeResult, error)
}

// KeyTree represents a hierarchical structure of keys, where each inner slice represents a layer of keys in the hierarchy.
type KeyTree [][]model.Key

type GetKeyChainQuery struct {
	KeyID    string
	TenantID string
}

type GetKeyChainResult struct {
	Keys []model.Key
}

type GetKeyTreeQuery struct {
	KeyID    string
	TenantID string
}

type GetKeyTreeResult struct {
	KeyTree KeyTree
}

// KeyTreeTraverser defines methods for traversing a KeyTree in different orders.
type KeyTreeTraverser interface {
	// IterKeysByLayerAsc iterates the keys layer by layer in ascending order (from root to leaf).
	IterKeysByLayerAsc() iter.Seq[[]model.Key]
	// IterKeysByLayerDsc iterates the keys layer by layer in descending order (from leaf to root).
	IterKeysByLayerDsc() iter.Seq[[]model.Key]
	// IterLayerAsc iterates the key kinds layer by layer in ascending order (from root to leaf).
	IterLayerAsc() iter.Seq[model.KeyKind]
	// IterLayerDsc iterates the key kinds layer by layer in descending order (from leaf to root).
	IterLayerDsc() iter.Seq[model.KeyKind]
}

var _ KeyTreeTraverser = KeyTree{}

// IterKeysByLayerAsc iterates the keys layer by layer in ascending order (from root to leaf).
func (kt KeyTree) IterKeysByLayerAsc() iter.Seq[[]model.Key] {
	return func(yield func([]model.Key) bool) {
		for _, layer := range kt {
			if !yield(layer) {
				return
			}
		}
	}
}

// IterKeysByLayerDsc iterates the keys layer by layer in descending order (from leaf to root).
func (kt KeyTree) IterKeysByLayerDsc() iter.Seq[[]model.Key] {
	return func(yield func([]model.Key) bool) {
		for _, layer := range slices.Backward(kt) {
			if !yield(layer) {
				return
			}
		}
	}
}

// IterLayerAsc iterates the key kinds layer by layer in ascending order (from root to leaf).
func (kt KeyTree) IterLayerAsc() iter.Seq[model.KeyKind] {
	return func(yield func(model.KeyKind) bool) {
		for _, layer := range kt {
			if len(layer) == 0 {
				continue
			}
			if !yield(layer[0].Kind) {
				return
			}
		}
	}
}

// IterLayerDsc iterates the key kinds layer by layer in descending order (from leaf to root).
func (kt KeyTree) IterLayerDsc() iter.Seq[model.KeyKind] {
	return func(yield func(model.KeyKind) bool) {
		for _, layer := range slices.Backward(kt) {
			if len(layer) == 0 {
				continue
			}
			if !yield(layer[0].Kind) {
				return
			}
		}
	}
}
