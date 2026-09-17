package sql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type Node string

const (
	Root  Node = "root"
	Agent Node = "agent"
)

const createSchemaMetaTable = `
CREATE TABLE IF NOT EXISTS schema_meta (
	node TEXT PRIMARY KEY
);
`

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

const keyTable = `
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
	UNIQUE (tenant_id, id)%s
);
`

const keysRootConstraints = `,
	FOREIGN KEY (tenant_id, parent_id) REFERENCES keys(tenant_id, id)`

var createKeysTable = fmt.Sprintf(keyTable, keysRootConstraints)
var createAgentsKeysTable = fmt.Sprintf(keyTable, "")

const keyVersionTable = `
CREATE TABLE IF NOT EXISTS key_versions (
	tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	key_id UUID NOT NULL,
	version INT NOT NULL,
	revision INT NOT NULL,
	parent_key_id UUID NULL,
	parent_key_version INT NULL,
	life_cycle_state TEXT NOT NULL,
	processing_state TEXT NOT NULL,
	created_at BIGINT NOT NULL,
	updated_at BIGINT NOT NULL,

	PRIMARY KEY (tenant_id, key_id, version, revision),
	FOREIGN KEY (tenant_id, key_id) REFERENCES keys(tenant_id, id)%s
);
`

const keyVersionsRootConstraints = `,
	FOREIGN KEY (tenant_id, parent_key_id, parent_key_version, revision)
		REFERENCES key_versions(tenant_id, key_id, version, revision)`

var createKeyVersionsTable = fmt.Sprintf(keyVersionTable, keyVersionsRootConstraints)
var createAgentsKeyVersionsTable = fmt.Sprintf(keyVersionTable, "")

func Migrate(ctx context.Context, db *sql.DB, n Node) error {
	switch n {
	case Root, Agent:
	default:
		return fmt.Errorf("migrate: unknown node %q", n)
	}

	if _, err := db.ExecContext(ctx, createSchemaMetaTable); err != nil {
		return fmt.Errorf("migrate: create schema_meta: %w", err)
	}

	var existing Node
	err := db.QueryRowContext(ctx, `SELECT node FROM schema_meta LIMIT 1`).Scan(&existing)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if _, err := db.ExecContext(ctx, `INSERT INTO schema_meta (node) VALUES ($1)`, n); err != nil {
			return fmt.Errorf("migrate: record node: %w", err)
		}
	case err != nil:
		return fmt.Errorf("migrate: read schema_meta: %w", err)
	case existing != n:
		return fmt.Errorf("migrate: database already initialized as %q, refusing to migrate as %q", existing, n)
	}

	stmts := []string{createTenantsTable}
	switch n {
	case Root:
		stmts = append(stmts,
			createAgentRegistrationsTable,
			createKeysTable,
			createKeyVersionsTable,
		)
	case Agent:
		stmts = append(stmts,
			createAgentsKeysTable,
			createAgentsKeyVersionsTable,
		)
	}

	for i, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: statement %d: %w", i, err)
		}
	}

	return nil
}
