package sql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

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
			return store.GetAgentResult{}, store.ErrAgentNotFound
		}
		return store.GetAgentResult{}, err
	}

	return store.GetAgentResult{
		Registration: reg,
	}, nil
}

func (s *AgentStore) UpdateStatus(ctx context.Context, q store.UpdateAgentStatusQuery) error {
	if len(q.FromStatus) == 0 {
		return fmt.Errorf("missing from status: %w", store.ErrAgentQueryInvalid)
	}
	if q.ToStatus == "" {
		return fmt.Errorf("missing to status: %w", store.ErrAgentQueryInvalid)
	}

	var sb strings.Builder
	now := clock.Now()

	sb.WriteString(`UPDATE agent_registrations
    SET status = $1, updated_at = $2
    WHERE status = ANY($3)`)
	args := []any{
		q.ToStatus,
		now,
		q.FromStatus,
	}

	if q.Name != "" {
		argIdx := len(args) + 1
		fmt.Fprintf(&sb, ` AND name = $%d`, argIdx)
		args = append(args, q.Name)
	}

	if q.InstanceID != "" {
		argIdx := len(args) + 1
		fmt.Fprintf(&sb, ` AND instance_id = $%d`, argIdx)
		args = append(args, q.InstanceID)
	}

	if q.HeartbeatThreshold > 0 {
		argIdx := len(args) + 1
		fmt.Fprintf(&sb, ` AND ($%d - last_heartbeat) > $%d`, argIdx, argIdx+1)
		args = append(args, now, q.HeartbeatThreshold.Nanoseconds())
	}
	_, err := s.db.ExecContext(ctx, sb.String(), args...)
	return err
}

func (s *AgentStore) Delete(ctx context.Context, q store.DeleteAgentQuery) error {
	if q.Status == "" {
		return fmt.Errorf("missing status: %w", store.ErrAgentQueryInvalid)
	}
	if q.HeartbeatThreshold <= 0 {
		return fmt.Errorf("invalid heartbeat threshold: %w", store.ErrAgentQueryInvalid)
	}

	now := clock.Now()
	stmt := `
	DELETE FROM agent_registrations
	WHERE status = $1 AND ($2 - last_heartbeat) > $3
	`
	_, err := s.db.ExecContext(ctx, stmt, q.Status, now, q.HeartbeatThreshold.Nanoseconds())
	return err
}

func (s *AgentStore) List(ctx context.Context, q store.ListAgentQuery) (store.ListAgentResult, error) {
	var sb strings.Builder
	sb.WriteString(`
	SELECT name, instance_id, status, last_heartbeat, created_at, updated_at
	FROM agent_registrations
	WHERE 1=1 `)

	var args []any
	if q.Name != "" {
		sb.WriteString(` AND name = $1`)
		args = append(args, q.Name)
	}

	rows, err := s.db.QueryContext(ctx, sb.String(), args...)
	if err != nil {
		return store.ListAgentResult{}, err
	}
	defer rows.Close()

	var registrations []core.AgentRegistration

	for rows.Next() {
		var reg core.AgentRegistration
		err := rows.Scan(
			&reg.Name,
			&reg.InstanceID,
			&reg.Status,
			&reg.LastHeartbeat,
			&reg.CreatedAt,
			&reg.UpdatedAt,
		)
		if err != nil {
			return store.ListAgentResult{}, err
		}
		registrations = append(registrations, reg)
	}

	if err := rows.Err(); err != nil {
		return store.ListAgentResult{}, err
	}

	return store.ListAgentResult{
		Registrations: registrations,
	}, nil
}
