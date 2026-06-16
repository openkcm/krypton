package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
)

var (
	ErrKeyNotFound      = errors.New("key not found")
	ErrKeyAlreadyExists = errors.New("key already exists")
)

type Key interface {
	CreateKey(ctx context.Context, key model.Key) error
	GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error)
	GetKeyByName(ctx context.Context, query GetKeyByNameQuery) (*model.Key, error)
	GetParentKeys(ctx context.Context, query GetParentKeysQuery) (GetParentKeysResult, error)
	GetDescendantKeys(ctx context.Context, query GetDescendantKeysQuery) (GetDescendantKeysResult, error)
	ListKeys(ctx context.Context, query ListKeysQuery) (ListKeysResult, error)
	UpdateKeyLifeCycleState(ctx context.Context, query UpdateKeyLifeCycleStateQuery) error
	UpdateKeyProcessingState(ctx context.Context, query UpdateKeyProcessingStateQuery) error
}

type GetKeyByNameQuery struct {
	TenantID string
	Name     string
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

type ListKeysQuery struct {
	TenantID              string
	Name                  string
	Kind                  model.KeyKind
	State                 model.KeyLifeCycleState
	ManagedBy             string
	Labels                model.Labels
	IsOrderByCreatedAtAsc bool
	Cursor                string
	Limit                 int
}

type ListKeysResult struct {
	Keys   []model.Key
	Cursor string
}

type UpdateKeyLifeCycleStateQuery struct {
	ID       string
	TenantID string
	NewState model.KeyLifeCycleState
}

type UpdateKeyProcessingStateQuery struct {
	ID        string
	TenantID  string
	NewStatus model.KeyProcessingStatus
	NewJobID  string
}
