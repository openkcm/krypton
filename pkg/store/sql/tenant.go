package sql

import (
	"context"
	"database/sql"
	"encoding/json/v2"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type TenantStore struct {
	db DBTX
}

var _ store.Tenant = &TenantStore{}

func NewTenantStore(db DBTX) *TenantStore {
	return &TenantStore{db: db}
}

func (ps *TenantStore) CreateTenant(ctx context.Context, query store.CreateTenantQuery) (store.CreateTenantResult, error) {
	stmt := `
		INSERT INTO tenants (id, name, labels, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`
	tenant := query.Tenant

	labelsJSON, err := json.Marshal(tenant.Labels)
	if err != nil {
		return store.CreateTenantResult{}, err
	}

	_, err = ps.db.ExecContext(ctx, stmt,
		tenant.ID,
		tenant.Name,
		labelsJSON,
		tenant.CreatedAt,
		tenant.UpdatedAt,
	)
	if err != nil {
		return store.CreateTenantResult{}, err
	}

	return store.CreateTenantResult{
		Tenant: tenant,
	}, nil
}

func (ps *TenantStore) GetTenant(ctx context.Context, query store.GetTenantQuery) (store.GetTenantResult, error) {
	stmt := `
		SELECT id, name, labels, created_at, updated_at
		FROM tenants
		WHERE id = $1
	`

	row := ps.db.QueryRowContext(ctx, stmt, query.ID)

	var tenant model.Tenant
	var labelsData []byte
	err := row.Scan(&tenant.ID, &tenant.Name, &labelsData, &tenant.CreatedAt, &tenant.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return store.GetTenantResult{}, store.ErrTenantNotFound
		}
		return store.GetTenantResult{}, err
	}

	if len(labelsData) > 0 {
		if err := json.Unmarshal(labelsData, &tenant.Labels); err != nil {
			return store.GetTenantResult{}, err
		}
	}

	return store.GetTenantResult{
		Tenant: tenant,
	}, nil
}

func (ps *TenantStore) ListTenants(ctx context.Context, _ store.ListTenantsQuery) (store.ListTenantsResult, error) {
	stmt := `
		SELECT id, name, labels, created_at, updated_at
		FROM tenants
	`

	rows, err := ps.db.QueryContext(ctx, stmt)
	if err != nil {
		return store.ListTenantsResult{}, err
	}
	defer rows.Close()

	var tenants []model.Tenant
	for rows.Next() {
		var tenant model.Tenant
		var labelsData []byte
		err := rows.Scan(&tenant.ID, &tenant.Name, &labelsData, &tenant.CreatedAt, &tenant.UpdatedAt)
		if err != nil {
			return store.ListTenantsResult{}, err
		}

		if len(labelsData) > 0 {
			if err := json.Unmarshal(labelsData, &tenant.Labels); err != nil {
				return store.ListTenantsResult{}, err
			}
		}

		tenants = append(tenants, tenant)
	}

	if err := rows.Err(); err != nil {
		return store.ListTenantsResult{}, err
	}

	return store.ListTenantsResult{
		Tenants: tenants,
	}, nil
}
