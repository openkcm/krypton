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
CREATE TABLE IF NOT EXISTS secrets (
	tenant_id TEXT NOT NULL CHECK(tenant_id != ''),
	id TEXT NOT NULL CHECK(id != ''),
	version INTEGER NOT NULL DEFAULT 0,
	revision INTEGER NOT NULL DEFAULT 0,
	secret BLOB NOT NULL,
	metadata BLOB,
	created_at INTEGER NOT NULL,
	PRIMARY KEY(tenant_id, id, version, revision)
)
`

type (
	// Unsafe is a SQLite Vault implementation backed by an unencrypted SQLite database.
	// It stores secrets in plaintext and is intended for local development and
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

// DestroyTenant removes all secrets associated with the given tenant from the vault.
func (u *Unsafe) DestroyTenant(ctx context.Context, req vault.DestroyTenantRequest) (*vault.DestroyTenantResponse, error) {
	_, err := u.db.ExecContext(ctx,
		"DELETE FROM secrets WHERE tenant_id = ?",
		req.TenantID,
	)
	if err != nil {
		return nil, err
	}
	return &vault.DestroyTenantResponse{}, nil
}

func (u *Unsafe) ImportSecret(ctx context.Context, req vault.ImportSecretRequest) (*vault.ImportSecretResponse, error) {
	if req.Secret == nil {
		return nil, vault.ErrInvalidRequest
	}
	_, err := u.db.ExecContext(ctx,
		`INSERT INTO secrets (tenant_id, id, version, revision, secret, metadata, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (tenant_id, id, version, revision) DO UPDATE SET secret = excluded.secret, metadata = excluded.metadata, created_at = excluded.created_at `,
		req.TenantID, req.ID, req.Version, req.Revision, []byte(req.Secret.SecureBytes()), req.Metadata, int64(clock.Now()),
	)
	if err != nil {
		return nil, err
	}
	return &vault.ImportSecretResponse{}, nil
}

func (u *Unsafe) ExportSecret(ctx context.Context, req vault.ExportSecretRequest) (*vault.ExportSecretResponse, error) {
	query := "SELECT secret, metadata FROM secrets WHERE tenant_id = ? AND id = ? AND version = ? AND revision = ?"
	args := []any{req.TenantID, req.ID, req.Version, req.Revision}

	var rawSecret []byte
	var metadata []byte
	err := u.db.QueryRowContext(ctx, query, args...).Scan(&rawSecret, &metadata)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, vault.ErrSecretNotFound
		}
		return nil, err
	}

	data, err := securemem.NewData("secret", len(rawSecret))
	if err != nil {
		return nil, err
	}
	copy(data.SecureBytes(), rawSecret)

	return &vault.ExportSecretResponse{
		Secret:   data,
		Metadata: metadata,
	}, nil
}

func (u *Unsafe) DestroySecret(ctx context.Context, req vault.DestroySecretRequest) (*vault.DestroySecretResponse, error) {
	_, err := u.db.ExecContext(ctx,
		"DELETE FROM secrets WHERE tenant_id = ? AND id = ? AND version = ? AND revision = ?",
		req.TenantID, req.ID, req.Version, req.Revision,
	)
	if err != nil {
		return nil, err
	}

	return &vault.DestroySecretResponse{}, nil
}

func (u *Unsafe) Info() vault.Info {
	return u.info
}

// Close closes the underlying database connection.
func (u *Unsafe) Close() error {
	return u.db.Close()
}
