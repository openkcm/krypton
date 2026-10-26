package common_test

import (
	"context"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/handler/common"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestValidateTenantID(t *testing.T) {
	db := newRootDB(t)
	transactor := storesql.NewTransactor(db)
	tenant := createTenant(t, db)

	t.Run("should return nil when tenant exists", func(t *testing.T) {
		// given
		step := common.ValidateTenantID(tenant.ID)

		// when
		err := store.ChainTransaction(t.Context(), transactor, step)

		// then
		assert.NoError(t, err)
	})

	t.Run("should return OrbitalFail when tenant is not found", func(t *testing.T) {
		// given
		step := common.ValidateTenantID(uuid.New().String())

		// when
		err := store.ChainTransaction(t.Context(), transactor, step)

		// then
		require.Error(t, err)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, err).Status)
	})

	t.Run("should return OrbitalContinue when DB is unavailable", func(t *testing.T) {
		// given
		brokenDB := newRootDB(t)
		_, execErr := brokenDB.ExecContext(t.Context(), "ALTER TABLE tenants RENAME TO tenants_hidden")
		require.NoError(t, execErr)

		brokenTransactor := storesql.NewTransactor(brokenDB)
		step := common.ValidateTenantID(tenant.ID)

		// when
		err := store.ChainTransaction(t.Context(), brokenTransactor, step)

		// then
		require.Error(t, err)
		assert.Equal(t, string(orbital.TaskStatusProcessing), applyResponse(t, err).Status)
	})
}

func TestEnsureKeyState(t *testing.T) {
	db := newRootDB(t)
	transactor := storesql.NewTransactor(db)
	kStore := storesql.NewKeyStore(db)
	tenant := createTenant(t, db)

	isActivePending := func(key *model.Key) bool {
		return key.LifeCycleState == model.KeyLifeCycleActive &&
			key.KeyProcessingState.Status == model.KeyProcessingPending
	}

	t.Run("should return nil when key matches condition", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: "root",
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		step := common.EnsureKeyState(handler.KeyIdentifier{ID: key.ID, TenantID: tenant.ID}, isActivePending)

		// when
		err := store.ChainTransaction(t.Context(), transactor, step)

		// then
		assert.NoError(t, err)
	})

	t.Run("should return OrbitalComplete when key does not match condition", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: "root",
			LifeCycleState:     model.KeyLifeCycleDeactivated,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		step := common.EnsureKeyState(handler.KeyIdentifier{ID: key.ID, TenantID: tenant.ID}, isActivePending)

		// when
		err := store.ChainTransaction(t.Context(), transactor, step)

		// then
		require.Error(t, err)
		assert.Equal(t, string(orbital.TaskStatusDone), applyResponse(t, err).Status)
	})

	t.Run("should return nil when condition is nil", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: "root",
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		step := common.EnsureKeyState(handler.KeyIdentifier{ID: key.ID, TenantID: tenant.ID}, nil)

		// when
		err := store.ChainTransaction(t.Context(), transactor, step)

		// then
		assert.NoError(t, err)
	})

	t.Run("should return OrbitalFail when key is not found", func(t *testing.T) {
		// given
		step := common.EnsureKeyState(handler.KeyIdentifier{ID: uuid.New().String(), TenantID: tenant.ID}, isActivePending)

		// when
		err := store.ChainTransaction(t.Context(), transactor, step)

		// then
		require.Error(t, err)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, err).Status)
	})

	t.Run("should return OrbitalContinue when DB is unavailable", func(t *testing.T) {
		// given
		brokenDB := newRootDB(t)
		brokenTenant := createTenant(t, brokenDB)
		brokenKStore := storesql.NewKeyStore(brokenDB)
		key := createKey(t, brokenKStore, model.Key{
			TenantID: brokenTenant.ID, Kind: "K0", ManagedBy: "root",
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		_, execErr := brokenDB.ExecContext(t.Context(), "ALTER TABLE keys RENAME TO keys_hidden")
		require.NoError(t, execErr)

		brokenTransactor := storesql.NewTransactor(brokenDB)
		step := common.EnsureKeyState(handler.KeyIdentifier{ID: key.ID, TenantID: brokenTenant.ID}, isActivePending)

		// when
		err := store.ChainTransaction(t.Context(), brokenTransactor, step)

		// then
		require.Error(t, err)
		assert.Equal(t, string(orbital.TaskStatusProcessing), applyResponse(t, err).Status)
	})
}

// applyResponse extracts the *OrbitalResponse from an error and returns the
// resulting task status after applying it to a HandlerResponse.
func applyResponse(t *testing.T, err error) orbital.TaskResponse {
	t.Helper()
	var or *common.OrbitalResponseError
	require.ErrorAs(t, err, &or)

	resp := orbital.ExecuteHandler(t.Context(), orbital.HandlerFunc(
		func(_ context.Context, _ orbital.HandlerRequest, r *orbital.HandlerResponse) {
			_ = or.Apply(r)
		},
	), orbital.TaskRequest{TaskID: uuid.New(), Type: "test"})
	return resp
}
