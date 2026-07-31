package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
)

var ErrKeyVersionNotFound = errors.New("key version not found")

type KeyVersion interface {
	CreateKeyVersion(ctx context.Context, query CreateKeyVersionQuery) (CreateKeyVersionResult, error)
	ListKeyVersions(ctx context.Context, query ListKeyVersionsQuery) (ListKeyVersionsResult, error)
}

type CreateKeyVersionQuery struct {
	KeyVersion model.KeyVersion
}

type CreateKeyVersionResult struct {
	KeyVersion model.KeyVersion
}

// KeyVersionOrder is a sort key for listing key versions. The zero value is
// invalid so accidental zero values fail instead of silently ordering.
type KeyVersionOrder int

const (
	KeyVersionOrderUnspecified KeyVersionOrder = iota
	KeyVersionOrderCreatedAtDesc
	KeyVersionOrderRevisionDesc
)

type ListKeyVersionsQuery struct {
	TenantID        string
	KeyID           string
	Version         string
	ProcessingState model.KeyVersionProcessingState
	// OrderBy applies the sort keys in the given order.
	OrderBy []KeyVersionOrder
	Limit   int
}

type ListKeyVersionsResult struct {
	KeyVersions []model.KeyVersion
}
