package store

import (
	"context"
	"errors"
	"fmt"
	"uuid"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/pkg/model"
)

var (
	ErrKeyNotFound       = errors.New("key not found")
	ErrKeyInsertConflict = errors.New("key insert skipped due to conflict")
	ErrInvalidQuery      = errors.New("invalid query")
)

type Key interface {
	CreateKey(ctx context.Context, key model.Key) error
	GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error)
	GetKeyByName(ctx context.Context, query GetKeyByNameQuery) (*model.Key, error)
	GetParentKeys(ctx context.Context, query GetParentKeysQuery) (GetParentKeysResult, error)
	GetDescendantKeys(ctx context.Context, query GetDescendantKeysQuery) (GetDescendantKeysResult, error)
	GetParentChildKeyLayers(ctx context.Context, query GetParentChildKeyLayersQuery) (GetParentChildKeyLayersResult, error)
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

// GetParentChildKeyLayersQuery walks parent-child layers from KeyID. Included
// children matching ParentFilters become the next layer's parents.
// Empty filter groups impose no restriction.
type GetParentChildKeyLayersQuery struct {
	KeyID         string
	TenantID      string
	ParentFilters []KeyFilter
	ChildFilters  []KeyFilter
	Depth         *int
}

type ParentChildKeyLayer struct {
	Parents  []model.Key
	Children []model.Key
}

type GetParentChildKeyLayersResult struct {
	Layers []ParentChildKeyLayer
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

func (q GetDescendantKeysQuery) Validate() error {
	return validateKeyTreeQuery(q.KeyID, q.TenantID, nil, q.Filters)
}

func (q GetParentChildKeyLayersQuery) Validate() error {
	return validateKeyTreeQuery(q.KeyID, q.TenantID, q.Depth, q.ParentFilters, q.ChildFilters)
}

func validateKeyTreeQuery(keyID, tenantID string, depth *int, filterGroups ...[]KeyFilter) error {
	if !isValidUUID(keyID) {
		return fmt.Errorf("%w: invalid query: KeyID must be a valid UUID, got %q", ErrInvalidQuery, keyID)
	}
	if !isValidUUID(tenantID) {
		return fmt.Errorf("%w: invalid query: TenantID must be a valid UUID, got %q", ErrInvalidQuery, tenantID)
	}
	if depth != nil && *depth < 1 {
		return fmt.Errorf("%w: invalid query: Depth must be at least 1, got %d", ErrInvalidQuery, *depth)
	}

	for _, filters := range filterGroups {
		for _, filter := range filters {
			if filter.LifeCycleState != "" && !keylifecycle.IsKnown(filter.LifeCycleState) {
				return fmt.Errorf("%w: invalid query: unknown lifecycle state %q", ErrInvalidQuery, filter.LifeCycleState)
			}
			for _, status := range filter.Status {
				if !model.IsKnownKeyStatus(status) {
					return fmt.Errorf("%w: invalid query: unknown processing status %q", ErrInvalidQuery, status)
				}
			}
		}
	}
	return nil
}

func isValidUUID(id string) bool {
	_, err := uuid.Parse(id)
	return err == nil
}
