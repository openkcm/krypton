package admin

import (
	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/model"
)

// TenantToProto converts a model.Tenant to a proto Tenant.
func TenantToProto(t model.Tenant) *Tenant {
	return &Tenant{
		Id:        t.ID,
		Name:      t.Name,
		Labels:    t.Labels,
		CreatedAt: int64(t.CreatedAt),
		UpdatedAt: int64(t.UpdatedAt),
	}
}

// TenantFromProto converts a proto Tenant to a model.Tenant.
func TenantFromProto(t *Tenant) model.Tenant {
	return model.Tenant{
		ID:        t.GetId(),
		Name:      t.GetName(),
		Labels:    t.GetLabels(),
		CreatedAt: clock.UnixNano(t.GetCreatedAt()),
		UpdatedAt: clock.UnixNano(t.GetUpdatedAt()),
	}
}

// TenantsToProto converts a slice of model.Tenant to proto Tenants.
func TenantsToProto(tenants []model.Tenant) []*Tenant {
	result := make([]*Tenant, len(tenants))
	for i, t := range tenants {
		result[i] = TenantToProto(t)
	}
	return result
}

// TenantsFromProto converts a slice of proto Tenants to model.Tenant.
func TenantsFromProto(tenants []*Tenant) []model.Tenant {
	result := make([]model.Tenant, len(tenants))
	for i, t := range tenants {
		result[i] = TenantFromProto(t)
	}
	return result
}
