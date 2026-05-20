package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
)

var ErrKeyNotFound = errors.New("key not found")

type Key interface {
	CreateKey(ctx context.Context, key model.Key) error
	GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error)
	GetKeyChain(ctx context.Context, query GetKeyChainQuery) (GetKeyChainResult, error)
	GetKeyTree(ctx context.Context, query GetKeyTreeQuery) (GetKeyTreeResult, error)
}

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
	KeyTree model.KeyTreeTraverser
}
