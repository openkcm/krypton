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

	_, err = ks.db.ExecContext(ctx, stmt,
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

func scanKey(row interface{ Scan(...any) error }) (*model.Key, error) {
	var key model.Key
	var kind string
	var labelsData []byte

	err := row.Scan(
		&key.ID,
		&key.TenantID,
		&kind,
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

	key.Kind = kind

	if len(labelsData) > 0 {
		if err := json.Unmarshal(labelsData, &key.Labels); err != nil {
			return nil, err
		}
	}

	return &key, nil
}
