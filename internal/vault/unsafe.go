package vault

import (
	"context"
	"database/sql"
	"errors"

	_ "modernc.org/sqlite"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/securemem"
)

// SQLiteMemory is the data source for an in-memory SQLite database with shared cache,
// allowing multiple connections from the same process to access the same database.
const SQLiteMemory SQLiteDataSource = "file::memory:?cache=shared"

const initDB = `
CREATE TABLE IF NOT EXISTS keys (
	tenant_id TEXT NOT NULL CHECK(tenant_id != ''),
	key_id TEXT NOT NULL CHECK(key_id != ''),
	key_version TEXT NOT NULL,
	key_material BLOB NOT NULL,
	aad BLOB,
	created_at INTEGER NOT NULL,
	PRIMARY KEY(tenant_id, key_id, key_version)
)
`

type (
	// UnsafeSQLite is a Vault implementation backed by an unencrypted SQLite database.
	// It stores key material in plaintext and is intended for local development and
	// testing only. Do not use in production.
	UnsafeSQLite struct {
		name   string
		source SQLiteDataSource
		db     *sql.DB
	}

	// SQLiteDataSource specifies the connection target for a SQLite database.
	SQLiteDataSource string
)

var _ Vault = &UnsafeSQLite{}

// NewUnsafeSQLite opens or creates an unencrypted SQLite vault at the given data source.
func NewUnsafeSQLite(ctx context.Context, name string, source SQLiteDataSource) (*UnsafeSQLite, error) {
	db, err := sql.Open("sqlite", string(source))
	if err != nil {
		return nil, err
	}
	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}
	v := &UnsafeSQLite{
		name:   name,
		source: source,
		db:     db,
	}
	err = v.migrate(ctx)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// SQLiteFile returns a SQLiteDataSource pointing to the given file path.
func SQLiteFile(path string) SQLiteDataSource {
	return SQLiteDataSource(path)
}

func (s *UnsafeSQLite) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, initDB)
	return err
}

func (s *UnsafeSQLite) ImportKey(ctx context.Context, req ImportKeyRequest) (*ImportKeyResponse, error) {
	if req.KeyMaterial == nil {
		return nil, ErrInvalidRequest
	}
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO keys (tenant_id, key_id, key_version, key_material, aad, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		req.TenantID, req.KeyID, req.KeyVersion, []byte(req.KeyMaterial.SecureBytes()), req.AAD, int64(clock.Now()),
	)
	if err != nil {
		return nil, err
	}
	return &ImportKeyResponse{}, nil
}

func (s *UnsafeSQLite) ExportKey(ctx context.Context, req ExportKeyRequest) (*ExportKeyResponse, error) {
	query := "SELECT key_material, aad FROM keys WHERE tenant_id = ? AND key_id = ? ORDER BY created_at DESC LIMIT 1"
	args := []any{req.TenantID, req.KeyID}
	if req.KeyVersion != "" {
		query = "SELECT key_material, aad FROM keys WHERE tenant_id = ? AND key_id = ? AND key_version = ?"
		args = append(args, req.KeyVersion)
	}

	var rawKey []byte
	var aad []byte
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&rawKey, &aad)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	data, err := securemem.NewData("", len(rawKey))
	if err != nil {
		return nil, err
	}
	copy(data.SecureBytes(), rawKey)

	return &ExportKeyResponse{
		KeyMaterial: data,
		AAD:         aad,
	}, nil
}

func (s *UnsafeSQLite) DestroyKey(ctx context.Context, req DestroyKeyRequest) (*DestroyKeyResponse, error) {
	rows, err := s.db.QueryContext(ctx,
		"DELETE FROM keys WHERE tenant_id = ? AND key_id = ? RETURNING key_version",
		req.TenantID, req.KeyID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var destroyed []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		destroyed = append(destroyed, version)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &DestroyKeyResponse{DestroyedVersions: destroyed}, nil
}

func (s *UnsafeSQLite) DestroyKeyVersion(ctx context.Context, req DestroyKeyVersionRequest) (*DestroyKeyVersionResponse, error) {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM keys WHERE tenant_id = ? AND key_id = ? AND key_version = ?",
		req.TenantID, req.KeyID, req.KeyVersion,
	)
	if err != nil {
		return nil, err
	}

	affected, err := result.RowsAffected()
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, ErrKeyNotFound
	}

	return &DestroyKeyVersionResponse{}, nil
}

func (s *UnsafeSQLite) Info() Info {
	source := "file"
	if s.source == SQLiteMemory {
		source = "memory"
	}
	return Info{
		Name: s.name,
		Type: "sqlite:" + source,
	}
}

// Close closes the underlying database connection.
func (s *UnsafeSQLite) Close() error {
	return s.db.Close()
}
