package store

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
)

var ErrTenantNotFound = errors.New("tenant not found")

type Tenant interface {
	UpsertTenant(ctx context.Context, query UpsertTenantQuery) (UpsertTenantResult, error)
	GetTenant(ctx context.Context, query GetTenantQuery) (GetTenantResult, error)
	ListTenants(ctx context.Context, query ListTenantsQuery) (ListTenantsResult, error)
}

type UpsertTenantQuery struct {
	Tenant model.Tenant
}

type UpsertTenantResult struct {
	Tenant model.Tenant
}

type GetTenantQuery struct {
	ID string
}

type GetTenantResult struct {
	Tenant model.Tenant
}

type ListTenantsQuery struct{}

type ListTenantsResult struct {
	Tenants []model.Tenant
}
