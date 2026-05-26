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
	GetParentKeys(ctx context.Context, query GetParentKeysQuery) (GetParentKeysResult, error)
	GetDescendantKeys(ctx context.Context, query GetDescendantKeysQuery) (GetDescendantKeysResult, error)
	UpdateKeyState(ctx context.Context, query UpdateKeyStateQuery) error
}

type GetParentKeysQuery struct {
	KeyID    string
	TenantID string
}

type GetParentKeysResult struct {
	Keys []model.Key
}

type GetDescendantKeysQuery struct {
	KeyID    string
	TenantID string
}

type GetDescendantKeysResult struct {
	KeyTree model.KeyTreeTraverser
}

type UpdateKeyStateQuery struct {
	ID       string
	TenantID string
	NewState model.KeyState
}
