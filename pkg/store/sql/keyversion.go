package sql

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type KeyVersionStore struct {
	db *sql.DB
}

var _ store.KeyVersion = &KeyVersionStore{}

func NewKeyVersionStore(db *sql.DB) *KeyVersionStore {
	return &KeyVersionStore{db: db}
}

func (s *KeyVersionStore) CreateKeyVersion(ctx context.Context, query store.CreateKeyVersionQuery) (store.CreateKeyVersionResult, error) {
	stmt := `
		INSERT INTO key_versions (tenant_id, key_id, version, revision, parent_key_id, parent_key_version, life_cycle_state, processing_state, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	kv := query.KeyVersion
	_, err := s.db.ExecContext(ctx, stmt,
		kv.TenantID,
		kv.KeyID,
		kv.Version,
		kv.Revision,
		kv.ParentKeyID,
		kv.ParentKeyVersion,
		kv.LifeCycleState,
		kv.ProcessingState,
		kv.CreatedAt,
		kv.UpdatedAt,
	)
	if err != nil {
		return store.CreateKeyVersionResult{}, err
	}

	return store.CreateKeyVersionResult{KeyVersion: kv}, nil
}

func (s *KeyVersionStore) ListKeyVersions(ctx context.Context, query store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
	params := make([]any, 0, 6)
	nextParam := func(v any) string {
		params = append(params, v)
		return fmt.Sprintf("$%d", len(params))
	}

	var q strings.Builder
	fmt.Fprintf(&q, `SELECT tenant_id, key_id, version, revision, parent_key_id, parent_key_version, life_cycle_state, processing_state, created_at, updated_at
		FROM key_versions WHERE tenant_id = %s `, nextParam(query.TenantID))

	if query.KeyID != "" {
		fmt.Fprintf(&q, "AND key_id = %s ", nextParam(query.KeyID))
	}
	if query.Version != "" {
		fmt.Fprintf(&q, "AND version = %s ", nextParam(query.Version))
	}
	if query.ProcessingState != "" {
		fmt.Fprintf(&q, "AND processing_state = %s ", nextParam(query.ProcessingState))
	}

	if query.IsOrderByRevisionDesc {
		q.WriteString("ORDER BY revision DESC ")
	}

	if query.Limit > 0 {
		fmt.Fprintf(&q, "LIMIT %s ", nextParam(query.Limit))
	}

	rows, err := s.db.QueryContext(ctx, q.String(), params...)
	if err != nil {
		return store.ListKeyVersionsResult{}, err
	}
	defer rows.Close()

	var keyVersions []model.KeyVersion
	for rows.Next() {
		var kv model.KeyVersion
		err := rows.Scan(
			&kv.TenantID,
			&kv.KeyID,
			&kv.Version,
			&kv.Revision,
			&kv.ParentKeyID,
			&kv.ParentKeyVersion,
			&kv.LifeCycleState,
			&kv.ProcessingState,
			&kv.CreatedAt,
			&kv.UpdatedAt,
		)
		if err != nil {
			return store.ListKeyVersionsResult{}, err
		}
		keyVersions = append(keyVersions, kv)
	}
	if err := rows.Err(); err != nil {
		return store.ListKeyVersionsResult{}, err
	}

	return store.ListKeyVersionsResult{KeyVersions: keyVersions}, nil
}
