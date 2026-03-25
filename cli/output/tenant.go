package output

import (
	"github.com/openkcm/krypton/pkg/api/admin"
)

const labelMaxLen = 25

// TenantTable implements the Table interface for displaying tenant data.
type TenantTable struct {
	TenantRows [][]string
}

// Header returns the column headers for tenant table output.
func (tt TenantTable) Header() []string {
	return []string{"ID", "NAME", "LABELS", "CREATED", "UPDATED"}
}

// Rows returns the rows of tenant data for table output.
func (tt TenantTable) Rows() [][]string {
	return tt.TenantRows
}

func fromCreateTenantResponse(r admin.CreateTenantResponse) TenantTable {
	return TenantTable{
		TenantRows: [][]string{tenantToRow(r.Tenant)},
	}
}

func fromGetTenantResponse(r admin.GetTenantResponse) TenantTable {
	return TenantTable{
		TenantRows: [][]string{tenantToRow(r.Tenant)},
	}
}

func fromListTenantsResponse(r admin.ListTenantsResponse) TenantTable {
	rows := make([][]string, len(r.Tenants))
	for i, t := range r.Tenants {
		rows[i] = tenantToRow(t)
	}
	return TenantTable{
		TenantRows: rows,
	}
}

func tenantToRow(t admin.Tenant) []string {
	return []string{
		t.ID,
		t.Name,
		formatLabels(t.Labels, labelMaxLen),
		formatRelativeTime(t.CreatedAt),
		formatRelativeTime(t.UpdatedAt),
	}
}
