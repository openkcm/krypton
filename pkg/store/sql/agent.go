package sql

import (
	"context"
	"database/sql"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/pkg/store"
)

type AgentStore struct {
	db *sql.DB
}

var _ store.Agent = &AgentStore{}

func NewAgentStore(ctx context.Context, db *sql.DB) (*AgentStore, error) {
	reg := &AgentStore{
		db: db,
	}

	stmt := `
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

	_, err := reg.db.ExecContext(ctx, stmt)
	if err != nil {
		return nil, err
	}

	return reg, nil
}

func (s *AgentStore) Register(ctx context.Context, q store.RegisterAgentQuery) (store.RegisterAgentResult, error) {
	r := q.Registration
	now := clock.Now()
	r.UpdatedAt = now
	r.CreatedAt = now

	stmt := `
	INSERT INTO agent_registrations (name, instance_id, status, last_heartbeat, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT (name, instance_id)
	DO UPDATE SET
    status = EXCLUDED.status,
    last_heartbeat = EXCLUDED.last_heartbeat,
    updated_at = EXCLUDED.updated_at
	RETURNING name, instance_id, status, last_heartbeat, created_at, updated_at
 `
	var result core.AgentRegistration
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
		return store.RegisterAgentResult{}, err
	}

	return store.RegisterAgentResult{
		Registration: result,
	}, nil
}

func (s *AgentStore) Get(ctx context.Context, q store.GetAgentQuery) (store.GetAgentResult, error) {
	stmt := `
		SELECT name, instance_id, status, last_heartbeat, created_at, updated_at
		FROM agent_registrations
		WHERE name = $1 AND instance_id = $2
	`
	var reg core.AgentRegistration
	err := s.db.QueryRowContext(ctx, stmt,
		q.Name,
		q.InstanceID).Scan(
		&reg.Name,
		&reg.InstanceID,
		&reg.Status,
		&reg.LastHeartbeat,
		&reg.CreatedAt,
		&reg.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return store.GetAgentResult{}, store.ErrAgentRegistrationNotFound
		}
		return store.GetAgentResult{}, err
	}

	return store.GetAgentResult{
		Registration: reg,
	}, nil
}
