package sql

import (
	"context"
	"database/sql"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/store"
)

type Registry struct {
	db *sql.DB
}

var _ store.Registry = &Registry{}

func NewRegistrySQL(ctx context.Context, db *sql.DB) (*Registry, error) {
	reg := &Registry{
		db: db,
	}

	stmt := `
	CREATE TABLE IF NOT EXISTS registry (
		name TEXT NOT NULL,
		instance_id UUID,
		status TEXT NOT NULL,
	  last_heartbeat BIGINT NOT NULL,
		created_at BIGINT NOT NULL,
		updated_at BIGINT NOT NULL,
 		PRIMARY KEY (name, instance_id)
	);
	`

	_, err := reg.db.ExecContext(ctx, stmt)
	if err != nil {
		return nil, err
	}

	return reg, nil
}

func (s *Registry) Upsert(ctx context.Context, in store.UpsertRegistryQuery) (store.UpsertRegistryResult, error) {
	r := in.Registry
	now := clock.Now()
	r.UpdatedAt = now
	r.CreatedAt = now

	stmt := `
	INSERT INTO registry (name, instance_id, status, last_heartbeat, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT (name, instance_id)
	DO UPDATE SET
    status = EXCLUDED.status,
    last_heartbeat = EXCLUDED.last_heartbeat,
    updated_at = EXCLUDED.updated_at
	RETURNING name, instance_id, status, last_heartbeat, created_at, updated_at
 `
	var result spec.Registry
	err := s.db.QueryRowContext(ctx, stmt,
		r.Name,
		r.InstanceID,
		r.Status,
		r.LastHeartbeat,
		r.CreatedAt,
		r.UpdatedAt,
	).Scan(
		&result.Name,
		&result.InstanceID,
		&result.Status,
		&result.LastHeartbeat,
		&result.CreatedAt,
		&result.UpdatedAt,
	)
	if err != nil {
		return store.UpsertRegistryResult{}, err
	}

	return store.UpsertRegistryResult{
		Registry: result,
	}, nil
}

func (s *Registry) Get(ctx context.Context, query store.GetRegistryQuery) (store.GetRegistryResult, error) {
	stmt := `
		SELECT name, instance_id, status, last_heartbeat, created_at, updated_at
		FROM registry
		WHERE name = $1 AND instance_id = $2
	`
	row := s.db.QueryRowContext(ctx, stmt, query.Name, query.InstanceID)

	var registry spec.Registry
	err := row.Scan(
		&registry.Name,
		&registry.InstanceID,
		&registry.Status,
		&registry.LastHeartbeat,
		&registry.CreatedAt,
		&registry.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return store.GetRegistryResult{}, store.ErrRegistryNotFound
		}
		return store.GetRegistryResult{}, err
	}

	return store.GetRegistryResult{
		Registry: registry,
	}, nil
}
