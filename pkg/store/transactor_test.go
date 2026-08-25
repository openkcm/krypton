package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/pkg/store"
)

type fakeTransactor func(context.Context, store.TransactionFunc) error

func (f fakeTransactor) Transaction(ctx context.Context, fn store.TransactionFunc) error {
	return f(ctx, fn)
}

type fakeValidator[T any] func(context.Context, store.Stores, T) error

func (f fakeValidator[T]) Validate(ctx context.Context, s store.Stores, in T) error {
	return f(ctx, s, in)
}

var passthroughTx = fakeTransactor(func(ctx context.Context, fn store.TransactionFunc) error {
	return fn(ctx, store.Stores{})
})

func TestValidatedTx_Run_NoValidators_InvokesFn(t *testing.T) {
	vt := store.NewValidatedTx[int](passthroughTx)

	var ran bool
	err := vt.Run(context.Background(), 42, func(_ context.Context, _ store.Stores, in int) error {
		ran = true
		assert.Equal(t, 42, in)
		return nil
	})

	require.NoError(t, err)
	assert.True(t, ran, "fn should have run")
}

func TestValidatedTx_Run_AllValidatorsPass_InvokesFn(t *testing.T) {
	v1 := fakeValidator[int](func(context.Context, store.Stores, int) error { return nil })
	v2 := fakeValidator[int](func(context.Context, store.Stores, int) error { return nil })
	vt := store.NewValidatedTx(passthroughTx, v1, v2)

	var ran bool
	err := vt.Run(context.Background(), 0, func(context.Context, store.Stores, int) error {
		ran = true
		return nil
	})

	require.NoError(t, err)
	assert.True(t, ran, "fn should have run when all validators pass")
}

func TestValidatedTx_Run_ValidatorReceivesStoresAndInput(t *testing.T) {
	wantStores := store.Stores{}
	tx := fakeTransactor(func(ctx context.Context, fn store.TransactionFunc) error {
		return fn(ctx, wantStores)
	})

	var gotStores store.Stores
	var gotIn string
	v := fakeValidator[string](func(_ context.Context, s store.Stores, in string) error {
		gotStores, gotIn = s, in
		return nil
	})
	vt := store.NewValidatedTx(tx, v)

	err := vt.Run(context.Background(), "hello", func(context.Context, store.Stores, string) error {
		return nil
	})

	require.NoError(t, err)
	assert.Equal(t, wantStores, gotStores)
	assert.Equal(t, "hello", gotIn)
}

func TestValidatedTx_Run_ValidatorFails_AbortsAndPropagates(t *testing.T) {
	sentinel := errors.New("validator failed")
	v := fakeValidator[int](func(context.Context, store.Stores, int) error { return sentinel })
	vt := store.NewValidatedTx(passthroughTx, v)

	var ran bool
	err := vt.Run(context.Background(), 0, func(context.Context, store.Stores, int) error {
		ran = true
		return nil
	})

	assert.ErrorIs(t, err, sentinel)
	assert.False(t, ran, "fn must not run when a validator fails")
}

func TestValidatedTx_Run_ValidatorsRunInOrder_FirstFailureShortCircuits(t *testing.T) {
	sentinel := errors.New("stop")
	var order []string

	v1 := fakeValidator[int](func(context.Context, store.Stores, int) error {
		order = append(order, "1")
		return nil
	})
	v2 := fakeValidator[int](func(context.Context, store.Stores, int) error {
		order = append(order, "2")
		return sentinel
	})
	v3 := fakeValidator[int](func(context.Context, store.Stores, int) error {
		order = append(order, "3")
		return nil
	})

	vt := store.NewValidatedTx(passthroughTx, v1, v2, v3)
	err := vt.Run(context.Background(), 0, func(context.Context, store.Stores, int) error {
		t.Fatal("fn must not run when a validator fails")
		return nil
	})

	assert.ErrorIs(t, err, sentinel)
	assert.Equal(t, []string{"1", "2"}, order,
		"validators run in declared order; the third must not run after the second fails")
}

func TestValidatedTx_Run_FnFails_PropagatesError(t *testing.T) {
	sentinel := errors.New("fn failed")
	vt := store.NewValidatedTx[int](passthroughTx)

	err := vt.Run(context.Background(), 0, func(context.Context, store.Stores, int) error {
		return sentinel
	})

	assert.ErrorIs(t, err, sentinel)
}

func TestValidatedTx_Run_TransactorFails_PropagatesError(t *testing.T) {
	sentinel := errors.New("begin failed")
	tx := fakeTransactor(func(context.Context, store.TransactionFunc) error {
		return sentinel
	})

	var validatorRan, fnRan bool
	v := fakeValidator[int](func(context.Context, store.Stores, int) error {
		validatorRan = true
		return nil
	})
	vt := store.NewValidatedTx(tx, v)

	err := vt.Run(context.Background(), 0, func(context.Context, store.Stores, int) error {
		fnRan = true
		return nil
	})

	assert.ErrorIs(t, err, sentinel)
	assert.False(t, validatorRan, "validator must not run when the transactor itself fails")
	assert.False(t, fnRan, "fn must not run when the transactor itself fails")
}
