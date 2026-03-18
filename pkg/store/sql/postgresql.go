package sql

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type PostgreSQL struct {
	db *sql.DB
}

var _ store.Store = &PostgreSQL{}

func NewPostgreSQL(ctx context.Context, db *sql.DB) (*PostgreSQL, error) {
	ps := &PostgreSQL{
		db: db,
	}

	stmt := `
	CREATE TABLE IF NOT EXISTS tenants (
		id UUID PRIMARY KEY,
		name TEXT NOT NULL,
		labels JSONB,
		created_at BIGINT NOT NULL,
		updated_at BIGINT NOT NULL
	);
	`

	_, err := ps.db.ExecContext(ctx, stmt)
	if err != nil {
		return nil, err
	}

	return ps, nil
}

func (ps *PostgreSQL) CreateTenant(ctx context.Context, tenant model.Tenant) (model.Tenant, error) {
	stmt := `
		INSERT INTO tenants (id, name, labels, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
	`

	labelsJSON, err := json.Marshal(tenant.Labels)
	if err != nil {
		return model.Tenant{}, err
	}

	_, err = ps.db.ExecContext(ctx, stmt,
		tenant.ID,
		tenant.Name,
		labelsJSON,
		tenant.CreatedAt,
		tenant.UpdatedAt,
	)
	if err != nil {
		return model.Tenant{}, err
	}

	return tenant, nil
}

func (ps *PostgreSQL) GetTenant(ctx context.Context, tenantID string) (model.Tenant, error) {
	stmt := `
		SELECT id, name, labels, created_at, updated_at
		FROM tenants
		WHERE id = $1
	`

	row := ps.db.QueryRowContext(ctx, stmt, tenantID)

	var tenant model.Tenant
	var labelsData []byte
	err := row.Scan(&tenant.ID, &tenant.Name, &labelsData, &tenant.CreatedAt, &tenant.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return model.Tenant{}, store.ErrTenantNotFound
		}
		return model.Tenant{}, err
	}

	if len(labelsData) > 0 {
		if err := json.Unmarshal(labelsData, &tenant.Labels); err != nil {
			return model.Tenant{}, err
		}
	}

	return tenant, nil
}
