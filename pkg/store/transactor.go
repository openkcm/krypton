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

// Validator returns a non-nil error when a precondition on the given input and Stores does not hold.
type Validator[T any] interface {
	Validate(ctx context.Context, stores Stores, in T) error
}

// ValidatedTxFunc operates on Stores and a typed input, returning an error to signal failure.
type ValidatedTxFunc[T any] func(ctx context.Context, stores Stores, in T) error

// ValidatedTx is a Transactor decorator that runs a fixed set of
// Validators inside a transaction and aborts on the first failure.
type ValidatedTx[T any] struct {
	transactor Transactor
	validators []Validator[T]
}

// NewValidatedTx returns a ValidatedTx.
func NewValidatedTx[T any](t Transactor, validators ...Validator[T]) *ValidatedTx[T] {
	return &ValidatedTx[T]{transactor: t, validators: validators}
}

// Run opens a transaction, then passes in and the transactional Stores to each Validator.
// If all validators pass, in and Stores are passed to fn.
func (v *ValidatedTx[T]) Run(ctx context.Context, in T, fn ValidatedTxFunc[T]) error {
	return v.transactor.Transaction(ctx, func(ctx context.Context, s Stores) error {
		for _, val := range v.validators {
			if err := val.Validate(ctx, s, in); err != nil {
				return err
			}
		}
		return fn(ctx, s, in)
	})
}
