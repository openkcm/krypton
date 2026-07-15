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

type ListKeyVersionsQuery struct {
	TenantID              string
	KeyID                 string
	Version               string
	ProcessingState       model.KeyVersionProcessingState
	IsOrderByRevisionDesc bool
	Limit                 int
}

type ListKeyVersionsResult struct {
	KeyVersions []model.KeyVersion
}
