package sql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// pgErrCodeUniqueViolation is the SQLSTATE value returned by Postgres on a
// unique-constraint violation (23505).
const pgErrCodeUniqueViolation = "23505"

type KeyStore struct {
	db *sql.DB
}

var _ store.Key = &KeyStore{}

func NewKeyStore(db *sql.DB) *KeyStore {
	return &KeyStore{db: db}
}

func (ks *KeyStore) CreateKey(ctx context.Context, key model.Key) error {
	stmt := `
		INSERT INTO keys (id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	labelsJSON, err := json.Marshal(key.Labels)
	if err != nil {
		return err
	}

	_, err = ks.db.ExecContext(
		ctx, stmt,
		key.ID,
		key.TenantID,
		key.Kind,
		key.Name,
		key.ParentID,
		key.ManagedBy,
		labelsJSON,
		key.LifeCycleState,
		key.KeyProcessingState.Status,
		nullableJobID(key.KeyProcessingState.JobID),
		key.CreatedAt,
		key.UpdatedAt,
	)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && string(pqErr.Code) == pgErrCodeUniqueViolation {
			return store.ErrKeyAlreadyExists
		}
		return err
	}
	return nil
}

func (ks *KeyStore) GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error) {
	stmt := `
		SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at
		FROM keys
		WHERE id = $1 AND tenant_id = $2
	`
	row := ks.db.QueryRowContext(ctx, stmt, id, tenantID)

	return scanKey(row)
}

func (ks *KeyStore) GetKeyByName(ctx context.Context, query store.GetKeyByNameQuery) (*model.Key, error) {
	stmt := `
		SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at
		FROM keys
		WHERE tenant_id = $1 AND name = $2
	`
	row := ks.db.QueryRowContext(ctx, stmt, query.TenantID, query.Name)

	return scanKey(row)
}

// GetParentKeys returns all ancestors of the given key (including itself) by traversing parent_id up to the root.
func (ks *KeyStore) GetParentKeys(ctx context.Context, query store.GetParentKeysQuery) (store.GetParentKeysResult, error) {
	stmt := `
		WITH RECURSIVE key_chain AS (
			SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at, 0 AS depth
			FROM keys
			WHERE id = $1 AND tenant_id = $2

			UNION ALL

			SELECT k.id, k.tenant_id, k.kind, k.name, k.parent_id, k.managed_by, k.labels, k.life_cycle_state, k.processing_status, k.processing_job_id, k.created_at, k.updated_at, kc.depth + 1
			FROM keys k
			INNER JOIN key_chain kc ON k.id = kc.parent_id AND k.tenant_id = kc.tenant_id
		)
		SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at
		FROM key_chain
		ORDER BY depth DESC
	`

	rows, err := ks.db.QueryContext(ctx, stmt, query.KeyID, query.TenantID)
	if err != nil {
		return store.GetParentKeysResult{}, err
	}
	defer rows.Close()

	var keys []model.Key
	for rows.Next() {
		key, err := scanKey(rows)
		if err != nil {
			return store.GetParentKeysResult{}, err
		}
		keys = append(keys, *key)
	}

	if err := rows.Err(); err != nil {
		return store.GetParentKeysResult{}, err
	}

	if len(keys) == 0 {
		return store.GetParentKeysResult{}, store.ErrKeyNotFound
	}

	return store.GetParentKeysResult{Keys: keys}, nil
}

// GetDescendantKeys returns all descendants of the given key (including itself)
// by traversing parent_id down to the leaves.
// The result is grouped by depth level.
func (ks *KeyStore) GetDescendantKeys(ctx context.Context, query store.GetDescendantKeysQuery) (store.GetDescendantKeysResult, error) {
	stmt := `
		WITH RECURSIVE key_tree AS (
			SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at, 0 AS depth
			FROM keys
			WHERE id = $1 AND tenant_id = $2

			UNION ALL

			SELECT k.id, k.tenant_id, k.kind, k.name, k.parent_id, k.managed_by, k.labels, k.life_cycle_state, k.processing_status, k.processing_job_id, k.created_at, k.updated_at, kt.depth + 1
			FROM keys k
			INNER JOIN key_tree kt ON k.parent_id = kt.id AND k.tenant_id = kt.tenant_id
		)
		SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at, depth
		FROM key_tree
		ORDER BY depth ASC, created_at ASC
	`

	rows, err := ks.db.QueryContext(ctx, stmt, query.KeyID, query.TenantID)
	if err != nil {
		return store.GetDescendantKeysResult{}, err
	}
	defer rows.Close()

	var layers model.KeyTree
	var found bool
	for rows.Next() {
		var key model.Key
		var labelsData []byte
		var processingJobID sql.NullString
		var depth int

		err := rows.Scan(
			&key.ID,
			&key.TenantID,
			&key.Kind,
			&key.Name,
			&key.ParentID,
			&key.ManagedBy,
			&labelsData,
			&key.LifeCycleState,
			&key.KeyProcessingState.Status,
			&processingJobID,
			&key.CreatedAt,
			&key.UpdatedAt,
			&depth,
		)
		if err != nil {
			return store.GetDescendantKeysResult{}, err
		}

		if processingJobID.Valid {
			key.KeyProcessingState.JobID = processingJobID.String
		}

		if len(labelsData) > 0 {
			if err := json.Unmarshal(labelsData, &key.Labels); err != nil {
				return store.GetDescendantKeysResult{}, err
			}
		}

		if depth == 0 {
			found = true
		}

		for len(layers) <= depth {
			layers = append(layers, nil)
		}
		layers[depth] = append(layers[depth], key)
	}

	if err := rows.Err(); err != nil {
		return store.GetDescendantKeysResult{}, err
	}

	if !found {
		return store.GetDescendantKeysResult{}, store.ErrKeyNotFound
	}

	return store.GetDescendantKeysResult{KeyTree: layers}, nil
}

func (ks *KeyStore) ListKeys(ctx context.Context, query store.ListKeysQuery) (store.ListKeysResult, error) {
	params := make([]any, 0, 12)
	nextParam := func(vals ...any) string {
		placeholders := make([]string, len(vals))
		for i, v := range vals {
			params = append(params, v)
			placeholders[i] = fmt.Sprintf("$%d", len(params))
		}
		return strings.Join(placeholders, ", ")
	}

	var q strings.Builder

	fmt.Fprintf(&q, `SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at 
	FROM keys 
	WHERE tenant_id = %s `, nextParam(query.TenantID))

	if query.Kind != "" {
		fmt.Fprintf(&q, "AND kind = %s ", nextParam(query.Kind))
	}

	if query.LifeCycleState != "" {
		fmt.Fprintf(&q, "AND life_cycle_state = %s ", nextParam(query.LifeCycleState))
	}

	if query.Name != "" {
		fmt.Fprintf(&q, "AND name ILIKE %s ", nextParam("%"+query.Name+"%"))
	}

	if query.ManagedBy != "" {
		fmt.Fprintf(&q, "AND managed_by = %s ", nextParam(query.ManagedBy))
	}

	if len(query.Labels) > 0 {
		labelJSON, err := json.Marshal(query.Labels)
		if err != nil {
			return store.ListKeysResult{}, err
		}
		fmt.Fprintf(&q, "AND labels @> %s::jsonb ", nextParam(string(labelJSON)))
	}

	if query.Cursor != "" {
		cursor, err := DecodeCursor(query.Cursor)
		if err != nil {
			return store.ListKeysResult{}, fmt.Errorf("invalid cursor: %w", err)
		}
		op := "<"
		if query.IsOrderByCreatedAtAsc {
			op = ">"
		}
		fmt.Fprintf(&q, "AND (created_at, id) %s (%s) ", op, nextParam(cursor.CreatedAt, cursor.ID))
	}

	if query.IsOrderByCreatedAtAsc {
		q.WriteString("ORDER BY created_at ASC, id ASC ")
	} else {
		q.WriteString("ORDER BY created_at DESC, id DESC ")
	}

	pageSize := query.Limit
	if pageSize <= 0 {
		pageSize = 50
	}
	fetchLimit := pageSize + 1

	fmt.Fprintf(&q, "LIMIT %s ", nextParam(fetchLimit))

	rows, err := ks.db.QueryContext(ctx, q.String(), params...)
	if err != nil {
		return store.ListKeysResult{}, err
	}
	defer rows.Close()

	keys := make([]model.Key, 0, fetchLimit)
	for rows.Next() {
		key, err := scanKey(rows)
		if err != nil {
			return store.ListKeysResult{}, err
		}
		keys = append(keys, *key)
	}
	if err := rows.Err(); err != nil {
		return store.ListKeysResult{}, err
	}

	var cursor string
	if len(keys) == fetchLimit {
		last := keys[pageSize-1]
		cursor, err = NewCursor(last.ID, last.CreatedAt).Encode()
		if err != nil {
			return store.ListKeysResult{}, err
		}
		keys = keys[:pageSize]
	}

	if len(keys) == 0 {
		return store.ListKeysResult{Keys: keys, Cursor: ""}, store.ErrKeyNotFound
	}

	return store.ListKeysResult{Keys: keys, Cursor: cursor}, nil
}

func (ks *KeyStore) UpdateKeyLifeCycleState(ctx context.Context, query store.UpdateKeyLifeCycleStateQuery) error {
	result, err := ks.db.ExecContext(ctx,
		`UPDATE keys SET life_cycle_state = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4`,
		query.NewState, clock.Now(), query.ID, query.TenantID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return store.ErrKeyNotFound
	}

	return nil
}

func (ks *KeyStore) UpdateKeyProcessingState(ctx context.Context, query store.UpdateKeyProcessingStateQuery) error {
	result, err := ks.db.ExecContext(ctx,
		`UPDATE keys SET processing_status = $1, processing_job_id = $2, updated_at = $3 WHERE id = $4 AND tenant_id = $5`,
		query.NewStatus, nullableJobID(query.NewJobID), clock.Now(), query.ID, query.TenantID,
	)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return store.ErrKeyNotFound
	}

	return nil
}

func (ks *KeyStore) UpdateKeyLifeCycleAndProcessingState(ctx context.Context, q store.UpdateKeyLifeCycleAndProcessingStateQuery) error {
	var sb strings.Builder
	sb.WriteString("UPDATE keys SET life_cycle_state = $1, processing_status = $2, updated_at = $3 WHERE id = $4 AND tenant_id = $5")

	args := []any{q.ToState, q.ToStatus, clock.Now(), q.ID, q.TenantID}
	argIdx := 6

	if len(q.FromState) > 0 {
		fmt.Fprintf(&sb, " AND life_cycle_state = ANY($%d)", argIdx)
		args = append(args, q.FromState)
		argIdx++
	}

	if len(q.FromStatus) > 0 {
		fmt.Fprintf(&sb, " AND processing_status = ANY($%d)", argIdx)
		args = append(args, q.FromStatus)
	}

	result, err := ks.db.ExecContext(ctx, sb.String(), args...)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return store.ErrKeyNotFound
	}

	return nil
}

func nullableJobID(jobID string) any {
	if jobID == "" {
		return nil
	}
	return jobID
}

func scanKey(row interface{ Scan(...any) error }) (*model.Key, error) {
	var key model.Key
	var labelsData []byte
	var processingJobID sql.NullString

	err := row.Scan(
		&key.ID,
		&key.TenantID,
		&key.Kind,
		&key.Name,
		&key.ParentID,
		&key.ManagedBy,
		&labelsData,
		&key.LifeCycleState,
		&key.KeyProcessingState.Status,
		&processingJobID,
		&key.CreatedAt,
		&key.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrKeyNotFound
		}
		return nil, err
	}

	if processingJobID.Valid {
		key.KeyProcessingState.JobID = processingJobID.String
	}

	if len(labelsData) > 0 {
		if err := json.Unmarshal(labelsData, &key.Labels); err != nil {
			return nil, err
		}
	}

	return &key, nil
}
