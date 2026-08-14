package sql_test

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestTransaction(t *testing.T) {
	ctx := t.Context()
	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	require.NoError(t, storesql.Migrate(ctx, db))

	tenantStore := storesql.NewTenantStore(db)
	keyStore := storesql.NewKeyStore(db)
	transactor := storesql.NewTransactor(db)

	tenant := createTenant(t, tenantStore)

	t.Run("should commit all writes when the function succeeds", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, "tx-commit-key", "K0", nil, "root", nil)

		// when
		err := transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
			return stores.Keys.CreateKey(ctx, key)
		})

		// then
		require.NoError(t, err)
		got, err := keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, key.ID, got.ID)
	})

	t.Run("should roll back all writes and return the error verbatim when the function fails", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, "tx-rollback-key", "K0", nil, "root", nil)
		errBoom := errors.New("boom")

		// when
		err := transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
			if err := stores.Keys.CreateKey(ctx, key); err != nil {
				return err
			}
			return errBoom
		})

		// then
		require.ErrorIs(t, err, errBoom)
		_, err = keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should roll back all writes when the function panics", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, "tx-panic-key", "K0", nil, "root", nil)

		// when
		require.PanicsWithValue(t, "boom", func() {
			_ = transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
				if err := stores.Keys.CreateKey(ctx, key); err != nil {
					return err
				}
				panic("boom")
			})
		})

		// then
		_, err := keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})

	t.Run("should make uncommitted writes visible to reads inside the transaction", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, "tx-read-own-write-key", "K0", nil, "root", nil)

		// when
		err := transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
			if err := stores.Keys.CreateKey(ctx, key); err != nil {
				return err
			}
			got, err := stores.Keys.GetKeyByID(ctx, key.ID, key.TenantID)
			if err != nil {
				return err
			}
			assert.Equal(t, key.ID, got.ID)
			return nil
		})

		// then
		require.NoError(t, err)
	})

	t.Run("should run nested calls as independent transactions", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, "tx-nested-key", "K0", nil, "root", nil)
		errBoom := errors.New("boom")

		// when
		err := transactor.Transaction(ctx, func(ctx context.Context, _ store.Stores) error {
			innerErr := transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
				return stores.Keys.CreateKey(ctx, key)
			})
			if innerErr != nil {
				return innerErr
			}
			return errBoom
		})

		// then: the inner transaction committed on its own, unaffected by
		// the outer rollback
		require.ErrorIs(t, err, errBoom)
		got, err := keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, key.ID, got.ID)
	})

	t.Run("should abort a conflicting transaction under serializable isolation", func(t *testing.T) {
		// given
		// classic write skew: each transaction reads the key the other
		// writes; read committed would commit both, serializable must
		// abort one with SQLSTATE 40001
		keyA := model.NewKey(tenant.ID, "tx-skew-key-a", "K0", nil, "root", nil)
		keyB := model.NewKey(tenant.ID, "tx-skew-key-b", "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, keyA))
		require.NoError(t, keyStore.CreateKey(ctx, keyB))

		var barrier sync.WaitGroup
		barrier.Add(2)
		runTx := func(readKey, writeKey model.Key) error {
			return transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
				_, err := stores.Keys.GetKeyByID(ctx, readKey.ID, readKey.TenantID)
				barrier.Done()
				if err != nil {
					return err
				}
				barrier.Wait()
				return stores.Keys.UpdateKeyLifeCycleState(ctx, store.UpdateKeyLifeCycleStateQuery{
					ID:       writeKey.ID,
					TenantID: writeKey.TenantID,
					NewState: model.KeyLifeCycleActive,
				})
			})
		}

		// when
		results := make(chan error, 2)
		go func() { results <- runTx(keyA, keyB) }()
		go func() { results <- runTx(keyB, keyA) }()

		// then
		failures := 0
		for range 2 {
			err := <-results
			if err == nil {
				continue
			}
			failures++
			var pqErr *pq.Error
			require.ErrorAs(t, err, &pqErr)
			assert.Equal(t, "40001", string(pqErr.Code))
		}
		require.GreaterOrEqual(t, failures, 1, "expected at least one transaction to be aborted by serialization conflict")
	})

	t.Run("should fail and commit nothing when the context is cancelled mid-transaction", func(t *testing.T) {
		// given
		key := model.NewKey(tenant.ID, "tx-cancel-key", "K0", nil, "root", nil)
		cancelCtx, cancel := context.WithCancel(ctx)
		t.Cleanup(cancel)

		// when
		err := transactor.Transaction(cancelCtx, func(ctx context.Context, stores store.Stores) error {
			if err := stores.Keys.CreateKey(ctx, key); err != nil {
				return err
			}
			cancel()
			return nil
		})

		// then
		require.Error(t, err)
		_, err = keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		assert.ErrorIs(t, err, store.ErrKeyNotFound)
	})
}
