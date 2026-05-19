package sql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type KeyStore struct {
	db *sql.DB
}

var _ store.Key = &KeyStore{}

func NewKeyStore(db *sql.DB) *KeyStore {
	return &KeyStore{db: db}
}

func (ks *KeyStore) CreateKey(ctx context.Context, key model.Key) error {
	stmt := `
		INSERT INTO keys (id, tenant_id, kind, name, parent_id, managed_by, labels, state, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
		key.State,
		key.CreatedAt,
		key.UpdatedAt,
	)
	return err
}

func (ks *KeyStore) GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error) {
	stmt := `
		SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, state, created_at, updated_at
		FROM keys
		WHERE id = $1 AND tenant_id = $2
	`
	row := ks.db.QueryRowContext(ctx, stmt, id, tenantID)

	return scanKey(row)
}

// GetKeyChain returns all ancestors of the given key (including itself) by traversing parent_id up to the root.
func (ks *KeyStore) GetKeyChain(ctx context.Context, query store.GetKeyChainQuery) (store.GetKeyChainResult, error) {
	stmt := `
		WITH RECURSIVE key_chain AS (
			SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, state, created_at, updated_at, 0 AS depth
			FROM keys
			WHERE id = $1 AND tenant_id = $2

			UNION ALL

			SELECT k.id, k.tenant_id, k.kind, k.name, k.parent_id, k.managed_by, k.labels, k.state, k.created_at, k.updated_at, kc.depth + 1
			FROM keys k
			INNER JOIN key_chain kc ON k.id = kc.parent_id AND k.tenant_id = kc.tenant_id
		)
		SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, state, created_at, updated_at
		FROM key_chain
		ORDER BY depth DESC
	`

	rows, err := ks.db.QueryContext(ctx, stmt, query.KeyID, query.TenantID)
	if err != nil {
		return store.GetKeyChainResult{}, err
	}
	defer rows.Close()

	var keys []model.Key
	for rows.Next() {
		key, err := scanKey(rows)
		if err != nil {
			return store.GetKeyChainResult{}, err
		}
		keys = append(keys, *key)
	}

	if err := rows.Err(); err != nil {
		return store.GetKeyChainResult{}, err
	}

	if len(keys) == 0 {
		return store.GetKeyChainResult{}, store.ErrKeyNotFound
	}

	return store.GetKeyChainResult{Keys: keys}, nil
}

// GetKeyTree returns all descendants of the given key (including itself)
// by traversing parent_id down to the leaves.
// The result is grouped by depth level.
func (ks *KeyStore) GetKeyTree(ctx context.Context, query store.GetKeyTreeQuery) (store.GetKeyTreeResult, error) {
	stmt := `
		WITH RECURSIVE key_tree AS (
			SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, state, created_at, updated_at, 0 AS depth
			FROM keys
			WHERE id = $1 AND tenant_id = $2

			UNION ALL

			SELECT k.id, k.tenant_id, k.kind, k.name, k.parent_id, k.managed_by, k.labels, k.state, k.created_at, k.updated_at, kt.depth + 1
			FROM keys k
			INNER JOIN key_tree kt ON k.parent_id = kt.id AND k.tenant_id = kt.tenant_id
		)
		SELECT id, tenant_id, kind, name, parent_id, managed_by, labels, state, created_at, updated_at, depth
		FROM key_tree
		ORDER BY depth ASC, created_at ASC
	`

	rows, err := ks.db.QueryContext(ctx, stmt, query.KeyID, query.TenantID)
	if err != nil {
		return store.GetKeyTreeResult{}, err
	}
	defer rows.Close()

	var layers [][]model.Key
	var found bool
	for rows.Next() {
		var key model.Key
		var labelsData []byte
		var depth int

		err := rows.Scan(
			&key.ID,
			&key.TenantID,
			&key.Kind,
			&key.Name,
			&key.ParentID,
			&key.ManagedBy,
			&labelsData,
			&key.State,
			&key.CreatedAt,
			&key.UpdatedAt,
			&depth,
		)
		if err != nil {
			return store.GetKeyTreeResult{}, err
		}

		if len(labelsData) > 0 {
			if err := json.Unmarshal(labelsData, &key.Labels); err != nil {
				return store.GetKeyTreeResult{}, err
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
		return store.GetKeyTreeResult{}, err
	}

	if !found {
		return store.GetKeyTreeResult{}, store.ErrKeyNotFound
	}

	return store.GetKeyTreeResult{KeyTree: layers}, nil
}

func scanKey(row interface{ Scan(...any) error }) (*model.Key, error) {
	var key model.Key
	var labelsData []byte

	err := row.Scan(
		&key.ID,
		&key.TenantID,
		&key.Kind,
		&key.Name,
		&key.ParentID,
		&key.ManagedBy,
		&labelsData,
		&key.State,
		&key.CreatedAt,
		&key.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, store.ErrKeyNotFound
		}
		return nil, err
	}

	if len(labelsData) > 0 {
		if err := json.Unmarshal(labelsData, &key.Labels); err != nil {
			return nil, err
		}
	}

	return &key, nil
}
