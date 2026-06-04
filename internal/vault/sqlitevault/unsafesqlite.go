package sqlitevault

import (
	"context"
	"database/sql"
	"errors"

	_ "modernc.org/sqlite"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
)

// MemorySource is the data source for an in-memory SQLite database with shared cache,
// allowing multiple connections from the same process to access the same database.
const MemorySource DataSource = "file::memory:?cache=shared"

const initDB = `
CREATE TABLE IF NOT EXISTS keys (
	tenant_id TEXT NOT NULL CHECK(tenant_id != ''),
	key_id TEXT NOT NULL CHECK(key_id != ''),
	key_version INTEGER NOT NULL,
	key_material BLOB NOT NULL,
	aad BLOB,
	created_at INTEGER NOT NULL,
	PRIMARY KEY(tenant_id, key_id, key_version)
)
`

type (
	// Unsafe is a SQLite Vault implementation backed by an unencrypted SQLite database.
	// It stores key material in plaintext and is intended for local development and
	// testing only. Do not use in production.
	Unsafe struct {
		name   string
		source DataSource
		db     *sql.DB
	}

	// DataSource specifies the connection target for a SQLite database.
	DataSource string
)

var _ vault.Vault = &Unsafe{}

// NewUnsafe opens or creates an unencrypted SQLite vault at the given data source.
func NewUnsafe(ctx context.Context, name string, source DataSource) (*Unsafe, error) {
	db, err := sql.Open("sqlite", string(source))
	if err != nil {
		return nil, err
	}
	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}
	v := &Unsafe{
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

// FileSource returns a DataSource pointing to the given file path.
func FileSource(path string) DataSource {
	return DataSource(path)
}

func (u *Unsafe) migrate(ctx context.Context) error {
	_, err := u.db.ExecContext(ctx, initDB)
	return err
}

func (u *Unsafe) ImportKey(ctx context.Context, req vault.ImportKeyRequest) (*vault.ImportKeyResponse, error) {
	if req.KeyMaterial == nil {
		return nil, vault.ErrInvalidRequest
	}
	_, err := u.db.ExecContext(ctx,
		"INSERT INTO keys (tenant_id, key_id, key_version, key_material, aad, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		req.TenantID, req.KeyID, req.KeyVersion, []byte(req.KeyMaterial.SecureBytes()), req.AAD, int64(clock.Now()),
	)
	if err != nil {
		return nil, err
	}
	return &vault.ImportKeyResponse{}, nil
}

func (u *Unsafe) ExportKey(ctx context.Context, req vault.ExportKeyRequest) (*vault.ExportKeyResponse, error) {
	query := "SELECT key_material, aad FROM keys WHERE tenant_id = ? AND key_id = ? ORDER BY key_version DESC LIMIT 1"
	args := []any{req.TenantID, req.KeyID}
	if req.KeyVersion != nil {
		query = "SELECT key_material, aad FROM keys WHERE tenant_id = ? AND key_id = ? AND key_version = ?"
		args = append(args, *req.KeyVersion)
	}

	var rawKey []byte
	var aad []byte
	err := u.db.QueryRowContext(ctx, query, args...).Scan(&rawKey, &aad)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrKeyNotFound
		}
		return nil, err
	}

	data, err := securemem.NewData("", len(rawKey))
	if err != nil {
		return nil, err
	}
	copy(data.SecureBytes(), rawKey)

	return &vault.ExportKeyResponse{
		KeyMaterial: data,
		AAD:         aad,
	}, nil
}

func (u *Unsafe) DestroyKey(ctx context.Context, req vault.DestroyKeyRequest) (*vault.DestroyKeyResponse, error) {
	rows, err := u.db.QueryContext(ctx,
		"DELETE FROM keys WHERE tenant_id = ? AND key_id = ? RETURNING key_version",
		req.TenantID, req.KeyID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var destroyed []int
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		destroyed = append(destroyed, version)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return &vault.DestroyKeyResponse{DestroyedVersions: destroyed}, nil
}

func (u *Unsafe) DestroyKeyVersion(ctx context.Context, req vault.DestroyKeyVersionRequest) (*vault.DestroyKeyVersionResponse, error) {
	result, err := u.db.ExecContext(ctx,
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
		return nil, vault.ErrKeyNotFound
	}

	return &vault.DestroyKeyVersionResponse{}, nil
}

func (u *Unsafe) Info() vault.Info {
	source := "file"
	if u.source == MemorySource {
		source = "memory"
	}
	return vault.Info{
		Name: u.name,
		Type: "sqlite:" + source,
	}
}

// Close closes the underlying database connection.
func (u *Unsafe) Close() error {
	return u.db.Close()
}
