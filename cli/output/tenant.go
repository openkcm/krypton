package output

import (
	"errors"

	"github.com/openkcm/krypton/pkg/api/admin"
)

const labelMaxLen = 25

var ErrUnsupportedResponse = errors.New("unsupported response type")

// Tenant represents a displayable tenant for table output.
type Tenant struct {
	ID        string
	Name      string
	Labels    map[string]string
	CreatedAt int64
	UpdatedAt int64
}

// TenantTable implements the Table interface for displaying tenant data.
type TenantTable struct {
	Tenants []Tenant
}

// Header returns the column headers for tenant table output.
func (tt TenantTable) Header() []string {
	return []string{"ID", "NAME", "LABELS", "CREATED", "UPDATED"}
}

// Rows returns the rows of tenant data for table output.
func (tt TenantTable) Rows() [][]string {
	rows := make([][]string, len(tt.Tenants))
	for i, t := range tt.Tenants {
		rows[i] = []string{
			t.ID,
			t.Name,
			formatLabels(t.Labels, labelMaxLen),
			formatRelativeTime(t.CreatedAt),
			formatRelativeTime(t.UpdatedAt),
		}
	}
	return rows
}

func fromCreateTenantResponse(r admin.CreateTenantResponse) Tenant {
	return Tenant{
		ID:        r.ID,
		Name:      r.Name,
		Labels:    r.Labels,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

func fromGetTenantResponse(r admin.GetTenantResponse) Tenant {
	return Tenant{
		ID:        r.ID,
		Name:      r.Name,
		Labels:    r.Labels,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
}

func fromListTenantsResponse(r admin.ListTenantsResponse) []Tenant {
	tenants := make([]Tenant, len(r.Tenants))
	for i, t := range r.Tenants {
		tenants[i] = Tenant{
			ID:        t.ID,
			Name:      t.Name,
			Labels:    t.Labels,
			CreatedAt: t.CreatedAt,
			UpdatedAt: t.UpdatedAt,
		}
	}
	return tenants
}
