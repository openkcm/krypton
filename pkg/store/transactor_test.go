package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/pkg/store"
)

func TestTransactorFunc(t *testing.T) {
	t.Run("should pass the stores through and return the function's error", func(t *testing.T) {
		// given
		stubStores := store.Stores{}
		errBoom := errors.New("boom")
		var passthrough store.Transactor = store.TransactorFunc(func(ctx context.Context, fn store.TransactionFunc) error {
			return fn(ctx, stubStores)
		})

		// when
		err := passthrough.Transaction(t.Context(), func(ctx context.Context, stores store.Stores) error {
			assert.Equal(t, stubStores, stores)
			return errBoom
		})

		// then
		require.ErrorIs(t, err, errBoom)
	})
}
