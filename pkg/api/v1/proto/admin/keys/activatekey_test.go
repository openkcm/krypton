package keys_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestActivateKey(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(ctx, db, storesql.Root))
	keyStore := storesql.NewKeyStore(db)
	tenantStore := storesql.NewTenantStore(db)
	svc := keypb.NewKeyService(
		config.RootConfig{},
		storesql.NewTransactor(db),
		keyStore,
		&noopJobGroupPreparer{},
		nil,
	)

	t.Run("should return error if input is not valid", func(t *testing.T) {
		// given
		svc := keypb.NewKeyService(config.RootConfig{}, nil, nil, nil, nil)

		tts := []struct {
			name  string
			input *keypb.ActivateKeyRequest
		}{
			{
				name:  "invalid uuid tenant id",
				input: &keypb.ActivateKeyRequest{TenantId: "invalid", Id: uuid.New().String()},
			},
			{
				name:  "empty tenant id",
				input: &keypb.ActivateKeyRequest{TenantId: "", Id: uuid.New().String()},
			},
			{
				name:  "invalid uuid key id",
				input: &keypb.ActivateKeyRequest{TenantId: uuid.New().String(), Id: "invalid"},
			},
			{
				name:  "empty key id",
				input: &keypb.ActivateKeyRequest{TenantId: uuid.New().String(), Id: ""},
			},
			{
				name:  "both tenant id and key id are invalid",
				input: &keypb.ActivateKeyRequest{TenantId: "not-a-uuid", Id: "also-not-a-uuid"},
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				res, err := svc.ActivateKey(ctx, tt.input)

				// then
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
				assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
			})
		}
	})

	t.Run("should return error if tenant is not found", func(t *testing.T) {
		// when
		res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: uuid.New().String(),
			Id:       uuid.New().String(),
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return error if key ID is not found", func(t *testing.T) {
		// given
		tenant := createTenant(t, tenantStore)

		// when
		res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       uuid.New().String(),
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return error if key state transition is not valid", func(t *testing.T) {
		tts := []struct {
			name  string
			state model.KeyLifeCycleState
		}{
			{
				name:  "deactivated to active",
				state: model.KeyLifeCycleDeactivated,
			},
			{
				name:  "destroyed to active",
				state: model.KeyLifeCycleDestroyed,
			},
			{
				name:  "compromised to active",
				state: model.KeyLifeCycleCompromised,
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				keyStore := storesql.NewKeyStore(db)
				tenantStore := storesql.NewTenantStore(db)
				svc := keypb.NewKeyService(
					config.RootConfig{},
					storesql.NewTransactor(db),
					keyStore,
					&noopJobGroupPreparer{},
					nil,
				)

				tenant := createTenant(t, tenantStore)

				// insert a key directly in a state that cannot transition to active
				key := newTestKey(t, keyStore, tenant.ID, "K0", nil, tt.state, model.KeyProcessingCompleted)

				// when
				res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
					TenantId: tenant.ID,
					Id:       key.ID,
				})

				// then
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, codes.FailedPrecondition, status.Code(err))
				assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
			})
		}
	})

	t.Run("should return error if parent key is not active and completed", func(t *testing.T) {
		tts := []struct {
			name             string
			parentState      model.KeyLifeCycleState
			parentProcessing model.KeyProcessingStatus
		}{
			{
				name:             "parent in pre-activation state",
				parentState:      model.KeyLifeCyclePreActivation,
				parentProcessing: model.KeyProcessingCompleted,
			},
			{
				name:             "parent active but processing in-progress",
				parentState:      model.KeyLifeCycleActive,
				parentProcessing: model.KeyProcessingInProgress,
			},
			{
				name:             "parent in suspended state",
				parentState:      model.KeyLifeCycleSuspended,
				parentProcessing: model.KeyProcessingCompleted,
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				tenant := createTenant(t, tenantStore)

				// create parent key (K0) in a state that is NOT active+completed
				parentKey := newTestKey(t, keyStore, tenant.ID, "K0", nil, tt.parentState, tt.parentProcessing)

				// create child key (K1) in pre-activation (valid transition to active)
				parentID := parentKey.ID
				childKey := newTestKey(t, keyStore, tenant.ID, "K1", &parentID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

				// when
				res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
					TenantId: tenant.ID,
					Id:       childKey.ID,
				})

				// then
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, codes.FailedPrecondition, status.Code(err))
				assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
			})
		}
	})

	t.Run("should return error if no keys are eligible for activation", func(t *testing.T) {
		tts := []struct {
			name             string
			processingStatus model.KeyProcessingStatus
		}{
			{
				name:             "key processing is pending",
				processingStatus: model.KeyProcessingPending,
			},
			{
				name:             "key processing is in-progress",
				processingStatus: model.KeyProcessingInProgress,
			},
			{
				name:             "key processing is failed",
				processingStatus: model.KeyProcessingFailed,
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				tenant := createTenant(t, tenantStore)

				// create a key in pre-activation (passes ValidateTransition) but
				// with non-completed processing so FilterKeys excludes it
				key := newTestKey(t, keyStore, tenant.ID, "K0", nil, model.KeyLifeCyclePreActivation, tt.processingStatus)

				// when
				res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
					TenantId: tenant.ID,
					Id:       key.ID,
				})

				// then
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, codes.FailedPrecondition, status.Code(err))
				assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
			})
		}
	})

	t.Run("should return error if UpdateKeyStates fails", func(t *testing.T) {
		// given
		errInjected := errors.New("injected update-key-states failure")
		transactor := &failingKeyTx{
			Transactor: storesql.NewTransactor(db),
			err:        errInjected,
		}
		svc := keypb.NewKeyService(
			config.RootConfig{},
			transactor,
			keyStore,
			&noopJobGroupPreparer{},
			nil,
		)

		tenant := createTenant(t, tenantStore)

		// create a root key in pre-activation + completed so it passes
		// all validators and FilterKeys, reaching UpdateKeyStates
		key := newTestKey(t, keyStore, tenant.ID, "K0", nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// when
		res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       key.ID,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should return error if PrepareJobGroup fails", func(t *testing.T) {
		// given
		errInjected := errors.New("injected preparer failure")
		svc := keypb.NewKeyService(
			config.RootConfig{},
			storesql.NewTransactor(db),
			keyStore,
			&spyJobGroupPreparer{err: errInjected},
			nil,
		)

		tenant := createTenant(t, tenantStore)

		// create a root key in pre-activation + completed so it passes
		// all validators, FilterKeys, and UpdateKeyStates, reaching PrepareJobGroup
		key := newTestKey(t, keyStore, tenant.ID, "K0", nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// when
		res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       key.ID,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should activate key and create job group", func(t *testing.T) {
		// given
		spy := &spyJobGroupPreparer{}
		svc := keypb.NewKeyService(
			config.RootConfig{},
			storesql.NewTransactor(db),
			keyStore,
			spy,
			nil,
		)

		tenant := createTenant(t, tenantStore)

		key := newTestKey(t, keyStore, tenant.ID, "K0", nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// when
		res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       key.ID,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify the key state was updated
		updatedKey, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, updatedKey.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedKey.KeyProcessingState.Status)

		// verify a job group was prepared with one job
		require.Len(t, spy.groups, 1)
		require.Len(t, spy.groups[0].Jobs, 1)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, key.ID)
	})

	t.Run("should activate 2 layers out of 3 and create 2 jobs", func(t *testing.T) {
		// given
		//   K0 (pre-activation + completed) ← activatable
		//     └── K1 (pre-activation + completed) ← activatable
		//           └── K2 (deactivated + completed) ← excluded (cannot transition to active)
		spy := &spyJobGroupPreparer{}
		svc := keypb.NewKeyService(
			config.RootConfig{},
			storesql.NewTransactor(db),
			keyStore,
			spy,
			nil,
		)

		tenant := createTenant(t, tenantStore)

		// layer 0: root key
		k0 := newTestKey(t, keyStore, tenant.ID, "K0", nil, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// layer 1: child key
		k0ID := k0.ID
		k1 := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// layer 2: grandchild key — deactivated, cannot transition to active
		k1ID := k1.ID
		k2 := newTestKey(t, keyStore, tenant.ID, "K2", &k1ID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		// when
		res, err := svc.ActivateKey(ctx, &keypb.ActivateKeyRequest{
			TenantId: tenant.ID,
			Id:       k0.ID,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify K0 and K1 are activated
		updatedK0, err := keyStore.GetKeyByID(ctx, k0.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, updatedK0.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK0.KeyProcessingState.Status)

		updatedK1, err := keyStore.GetKeyByID(ctx, k1.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, updatedK1.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK1.KeyProcessingState.Status)

		// verify K2 was not activated (still deactivated)
		updatedK2, err := keyStore.GetKeyByID(ctx, k2.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleDeactivated, updatedK2.LifeCycleState)

		// verify 2 jobs were created (one per activatable layer)
		require.Len(t, spy.groups, 1)
		require.Len(t, spy.groups[0].Jobs, 2)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, k0.ID)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[1].Data, k1.ID)
	})
}

// newTestKey creates a key with the given state and processing status, inserts
// it into the store, and returns it. Mirrors the createKey helper in the
// internal/handler/activatekey package tests.
func newTestKey(t *testing.T, ks store.Key, tenantID, kind string, parentID *string, state model.KeyLifeCycleState, processing model.KeyProcessingStatus) model.Key {
	t.Helper()
	key := model.NewKey(tenantID, kind+"-"+uuid.New().String(), kind, parentID, testRootName, nil)
	key.LifeCycleState = state
	key.KeyProcessingState = model.KeyProcessingState{Status: processing}
	require.NoError(t, ks.CreateKey(t.Context(), key))
	return key
}

// assertJobDataContainsKeys unmarshals a job's Data field and verifies it
// contains exactly the given key IDs (order-independent).
func assertJobDataContainsKeys(t *testing.T, jobData []byte, expectedKeyIDs ...string) {
	t.Helper()
	var keys []model.Key
	require.NoError(t, json.Unmarshal(jobData, &keys))
	actualIDs := make([]string, 0, len(keys))
	for _, k := range keys {
		actualIDs = append(actualIDs, k.ID)
	}
	assert.ElementsMatch(t, expectedKeyIDs, actualIDs)
}

// stubKeyStateUpdater wraps a real key store and fails only
// UpdateKeyStates, so the injected error hits inside the transaction.
type stubKeyStateUpdater struct {
	store.Key

	err error
}

func (s *stubKeyStateUpdater) UpdateKeyStates(context.Context, store.UpdateKeyStatesQuery) error {
	return s.err
}

// failingKeyTx wraps a real transactor and swaps the transaction's
// key store for a failing one.
type failingKeyTx struct {
	store.Transactor

	err error
}

func (f *failingKeyTx) Transaction(ctx context.Context, fn store.TransactionFunc) error {
	return f.Transactor.Transaction(ctx, func(ctx context.Context, stores store.Stores) error {
		stores.Keys = &stubKeyStateUpdater{Key: stores.Keys, err: f.err}
		return fn(ctx, stores)
	})
}
