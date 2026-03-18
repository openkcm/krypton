package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
)

var ErrTenantNotFound = errors.New("tenant not found")

type Store interface {
	CreateTenant(ctx context.Context, tenant model.Tenant) (model.Tenant, error)
	GetTenant(ctx context.Context, id string) (model.Tenant, error)
}
