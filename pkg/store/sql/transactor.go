package sql

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openkcm/krypton/pkg/store"
)

// DBTX is the subset of *sql.DB and *sql.Tx the stores execute statements
// through, letting the same store methods run on the pool or inside a
// transaction.
type DBTX interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

var (
	_ DBTX = (*sql.DB)(nil)
	_ DBTX = (*sql.Tx)(nil)
)

// Transactor implements store.Transactor on the same *sql.DB handle the
// stores were built with.
type Transactor struct {
	db *sql.DB
}

var _ store.Transactor = &Transactor{}

func NewTransactor(db *sql.DB) *Transactor {
	return &Transactor{db: db}
}

func (t *Transactor) Transaction(ctx context.Context, fn store.TransactionFunc) error {
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			// Reached on fn error, Commit error, or panic (the panic keeps
			// unwinding). Rollback after a failed Commit returns
			// sql.ErrTxDone, which is harmless.
			_ = tx.Rollback()
		}
	}()

	err = fn(ctx, store.Stores{
		Tenants:     NewTenantStore(tx),
		Agents:      NewAgentStore(tx),
		Keys:        NewKeyStore(tx),
		KeyVersions: NewKeyVersionStore(tx),
	})
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	return nil
}
