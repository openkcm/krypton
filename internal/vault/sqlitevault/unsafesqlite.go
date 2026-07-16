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
	key_version TEXT NOT NULL,
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
		info vault.Info
		db   *sql.DB
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
	t := TypeUnsafe
	if source == MemorySource {
		t = TypeUnsafeMemory
	}
	v := &Unsafe{
		info: vault.Info{
			Name: name,
			Type: t,
		},
		db: db,
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

// PrepareTenant creates a new tenant in the vault. In this unsafe implementation, it does nothing.
func (u *Unsafe) PrepareTenant(ctx context.Context, req vault.PrepareTenantRequest) (*vault.PrepareTenantResponse, error) {
	return &vault.PrepareTenantResponse{}, nil
}

// DestroyTenant removes all keys associated with the given tenant from the vault.
func (u *Unsafe) DestroyTenant(ctx context.Context, req vault.DestroyTenantRequest) (*vault.DestroyTenantResponse, error) {
	_, err := u.db.ExecContext(ctx,
		"DELETE FROM keys WHERE tenant_id = ?",
		req.TenantID,
	)
	if err != nil {
		return nil, err
	}
	return &vault.DestroyTenantResponse{}, nil
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
	query := "SELECT key_material, aad FROM keys WHERE tenant_id = ? AND key_id = ? AND key_version = ?"
	args := []any{req.TenantID, req.KeyID, req.KeyVersion}

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
	_, err := u.db.ExecContext(ctx,
		"DELETE FROM keys WHERE tenant_id = ? AND key_id = ? AND key_version = ?",
		req.TenantID, req.KeyID, req.KeyVersion,
	)
	if err != nil {
		return nil, err
	}

	return &vault.DestroyKeyResponse{}, nil
}

func (u *Unsafe) Info() vault.Info {
	return u.info
}

// Close closes the underlying database connection.
func (u *Unsafe) Close() error {
	return u.db.Close()
}
