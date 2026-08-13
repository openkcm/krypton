package store

import "context"

// Stores bundles every store interface bound to one database handle. The
// bundle passed to a TransactionFunc is bound to a single transaction.
type Stores struct {
	Tenants     Tenant
	Agents      Agent
	Keys        Key
	KeyVersions KeyVersion
}

// TransactionFunc is the callback signature for Transactor.Transaction.
type TransactionFunc func(ctx context.Context, stores Stores) error

// Transactor runs fn inside a single database transaction: every call made
// on the Stores passed to fn joins that transaction. If fn returns an
// error or panics the transaction is rolled back, otherwise it is
// committed. A nested call opens an independent transaction. The Stores
// passed to fn must not outlive fn or be shared across goroutines, as the
// transaction they are bound to is not goroutine-safe.
type Transactor interface {
	Transaction(ctx context.Context, fn TransactionFunc) error
}

// TransactorFunc adapts a function to the Transactor interface, allowing
// tests to substitute a passthrough transactor:
//
//	store.TransactorFunc(func(ctx context.Context, fn store.TransactionFunc) error {
//		return fn(ctx, store.Stores{Keys: stubKeys})
//	})
type TransactorFunc func(ctx context.Context, fn TransactionFunc) error

func (f TransactorFunc) Transaction(ctx context.Context, fn TransactionFunc) error {
	return f(ctx, fn)
}
