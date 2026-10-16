package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
)

var (
	ErrKeyNotFound       = errors.New("key not found")
	ErrKeyInsertConflict = errors.New("key insert skipped due to conflict")
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
	UpdateKeyStates(ctx context.Context, query UpdateKeyStatesQuery) error
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

// KeyFilter represents a single filter condition for descendant key queries.
// Within a filter, non-empty fields are AND'd together. Across multiple
// filters in a query, they are OR'd: a key passes if it matches at least one.
//
// Both fields are optional. When LifeCycleState is empty, any lifecycle state
// matches. When Status is empty, any processing status matches. A filter with
// all fields at their zero value produces no condition and is ignored.
type KeyFilter struct {
	LifeCycleState model.KeyLifeCycleState
	Status         []model.KeyProcessingStatus
}

type GetDescendantKeysQuery struct {
	KeyID    string
	TenantID string
	Filters  []KeyFilter
}

type GetDescendantKeysResult struct {
	KeyTree model.KeyTreeTraverser
}

type ListKeysQuery struct {
	TenantID              string
	Name                  string
	Kind                  model.KeyKind
	LifeCycleState        model.KeyLifeCycleState
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

type UpdateKeyStatesQuery struct {
	ID         string
	TenantID   string
	ToState    model.KeyLifeCycleState
	ToStatus   model.KeyProcessingStatus
	FromState  []model.KeyLifeCycleState
	FromStatus []model.KeyProcessingStatus
}
