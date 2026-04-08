package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
)

var ErrTenantNotFound = errors.New("tenant not found")

type Store interface {
	CreateTenant(ctx context.Context, query CreateTenantQuery) (CreateTenantResult, error)
	GetTenant(ctx context.Context, query GetTenantQuery) (GetTenantResult, error)
	ListTenants(ctx context.Context, query ListTenantsQuery) (ListTenantsResult, error)
}

type CreateTenantQuery struct {
	Tenant model.Tenant
}

type CreateTenantResult struct {
	Tenant model.Tenant
}

type GetTenantQuery struct {
	ID string
}

type GetTenantResult struct {
	Tenant model.Tenant
}

type ListTenantsQuery struct {
}

type ListTenantsResult struct {
	Tenants []model.Tenant
}
