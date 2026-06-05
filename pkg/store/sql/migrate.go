package sql

import (
	"context"
	"database/sql"
)

const createTenantsTable = `
CREATE TABLE IF NOT EXISTS tenants (
	id UUID PRIMARY KEY,
	name TEXT NOT NULL,
	labels JSONB,
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL
);
`

const createAgentRegistrationsTable = `
CREATE TABLE IF NOT EXISTS agent_registrations (
	name TEXT NOT NULL,
	instance_id UUID,
	status TEXT NOT NULL,
	last_heartbeat BIGINT NOT NULL,
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL,
	PRIMARY KEY (name, instance_id)
);
`

const createKeysTable = `
CREATE TABLE IF NOT EXISTS keys (
	id UUID PRIMARY KEY,
	tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	kind TEXT NOT NULL,
	name TEXT NOT NULL,
	parent_id UUID NULL,
	managed_by TEXT NOT NULL,
	labels JSONB,
	life_cycle_state TEXT NOT NULL,
	processing_status TEXT NOT NULL DEFAULT 'pending',
	processing_job_id UUID NULL,
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL,

	UNIQUE (tenant_id, name),
	UNIQUE (tenant_id, id),
	FOREIGN KEY (tenant_id, parent_id) REFERENCES keys(tenant_id, id)
);
`

func Migrate(ctx context.Context, db *sql.DB) error {
	stmts := []string{
		createTenantsTable,
		createAgentRegistrationsTable,
		createKeysTable,
	}

	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}

	return nil
}
