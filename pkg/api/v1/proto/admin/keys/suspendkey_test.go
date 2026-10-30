package keys_test

import (
	"errors"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/handler/suspendkey"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestSuspendKey(t *testing.T) {
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
			input *keypb.SuspendKeyRequest
		}{
			{
				name:  "invalid uuid tenant id",
				input: &keypb.SuspendKeyRequest{TenantId: "invalid", Id: uuid.New().String()},
			},
			{
				name:  "empty tenant id",
				input: &keypb.SuspendKeyRequest{TenantId: "", Id: uuid.New().String()},
			},
			{
				name:  "invalid uuid key id",
				input: &keypb.SuspendKeyRequest{TenantId: uuid.New().String(), Id: "invalid"},
			},
			{
				name:  "empty key id",
				input: &keypb.SuspendKeyRequest{TenantId: uuid.New().String(), Id: ""},
			},
			{
				name:  "both tenant id and key id are invalid",
				input: &keypb.SuspendKeyRequest{TenantId: "not-a-uuid", Id: "also-not-a-uuid"},
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				res, err := svc.SuspendKey(ctx, tt.input)

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
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
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
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
			TenantId: tenant.ID,
			Id:       uuid.New().String(),
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.NotFound, status.Code(err), err)
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return error if key ID is not found for cascading", func(t *testing.T) {
		// given
		tenant := createTenant(t, tenantStore)

		// when
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
			TenantId:  tenant.ID,
			Id:        uuid.New().String(),
			Cascading: true,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.NotFound, status.Code(err), err)
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return error if key state transition is not valid", func(t *testing.T) {
		tts := []struct {
			name  string
			state model.KeyLifeCycleState
		}{
			{
				name:  "deactivated to suspend",
				state: model.KeyLifeCycleDeactivated,
			},
			{
				name:  "destroyed to suspend",
				state: model.KeyLifeCycleDestroyed,
			},
			{
				name:  "compromised to suspend",
				state: model.KeyLifeCycleCompromised,
			},
			{
				name:  "pre-activation to suspend",
				state: model.KeyLifeCyclePreActivation,
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

				// insert a key directly in a state that cannot transition to suspended
				key := newTestKey(
					t,
					keyStore,
					tenant.ID,
					"K0",
					nil,
					tt.state,
					model.KeyProcessingCompleted,
				)

				// when
				res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
					TenantId: tenant.ID,
					Id:       key.ID,
				})

				// then
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, codes.NotFound, status.Code(err))
				assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
			})
		}
	})

	t.Run("should return error if no keys are eligible for suspension", func(t *testing.T) {
		tts := []struct {
			name             string
			processingStatus model.KeyProcessingStatus
			keyState         model.KeyLifeCycleState
		}{
			{
				name:             "key processing is pending and key is active",
				processingStatus: model.KeyProcessingPending,
				keyState:         model.KeyLifeCycleActive,
			},
			{
				name:             "key processing is in-progress and key is active",
				processingStatus: model.KeyProcessingInProgress,
				keyState:         model.KeyLifeCycleActive,
			},
			{
				name:             "key processing is failed and key is active",
				processingStatus: model.KeyProcessingFailed,
				keyState:         model.KeyLifeCycleActive,
			},
			{
				name:             "key processing is pending and key is suspended",
				processingStatus: model.KeyProcessingPending,
				keyState:         model.KeyLifeCycleSuspended,
			},
			{
				name:             "key processing is in-progress and key is suspended",
				processingStatus: model.KeyProcessingInProgress,
				keyState:         model.KeyLifeCycleSuspended,
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				tenant := createTenant(t, tenantStore)

				// create a key in active (passes ValidateTransition) but
				// with non-completed processing so the selector excludes it
				key := newTestKey(
					t,
					keyStore,
					tenant.ID,
					"K0",
					nil,
					tt.keyState,
					tt.processingStatus,
				)

				// when
				res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
					TenantId: tenant.ID,
					Id:       key.ID,
				})

				// then
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, codes.NotFound, status.Code(err))
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

		// create a root key in active + completed so it passes
		// all validators and the selector, reaching UpdateKeyStates
		key := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K0",
			nil,
			model.KeyLifeCycleActive,
			model.KeyProcessingCompleted,
		)

		// when
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
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

		// create a root key in active + completed so it passes
		// all validators, the selector, and UpdateKeyStates, reaching PrepareJobGroup
		key := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K0",
			nil,
			model.KeyLifeCycleActive,
			model.KeyProcessingCompleted,
		)

		// when
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
			TenantId: tenant.ID,
			Id:       key.ID,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should return error if key is already suspended and completed", func(t *testing.T) {
		// given — key is already suspended + completed; no transition needed.
		tenant := createTenant(t, tenantStore)
		key := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K0",
			nil,
			model.KeyLifeCycleSuspended,
			model.KeyProcessingCompleted,
		)

		// when
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
			TenantId: tenant.ID,
			Id:       key.ID,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)

		// verify the key state was not modified
		unchanged, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleSuspended, unchanged.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchanged.KeyProcessingState.Status)
	})

	t.Run("should skip already suspended root and suspend children with cascading", func(t *testing.T) {
		// given — root is already suspended + completed, child is active + completed.
		//
		//   K0 (suspended + completed) ← skipped (already in target state)
		//     └── K1 (active + completed) ← suspendable
		spy := &spyJobGroupPreparer{}
		svc := keypb.NewKeyService(
			config.RootConfig{},
			storesql.NewTransactor(db),
			keyStore,
			spy,
			nil,
		)

		tenant := createTenant(t, tenantStore)
		root := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K0",
			nil,
			model.KeyLifeCycleSuspended,
			model.KeyProcessingCompleted,
		)
		rootID := root.ID
		child := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K1",
			&rootID,
			model.KeyLifeCycleActive,
			model.KeyProcessingCompleted,
		)

		// when
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
			TenantId:  tenant.ID,
			Id:        root.ID,
			Cascading: true,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify root was not modified (already suspended + completed)
		unchangedRoot, err := keyStore.GetKeyByID(ctx, root.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleSuspended, unchangedRoot.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedRoot.KeyProcessingState.Status)

		// verify child was suspended
		updatedChild, err := keyStore.GetKeyByID(ctx, child.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleSuspended, updatedChild.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedChild.KeyProcessingState.Status)

		// verify 1 job was created (child only, root skipped)
		require.Len(t, spy.groups, 1)
		assert.Equal(t, suspendkey.JobGroupType, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 1)
		assert.Equal(t, suspendkey.JobType, spy.groups[0].Jobs[0].Type)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, child.ID)
		assertJobDataTenantID(t, spy.groups[0].Jobs[0].Data, tenant.ID)
	})

	t.Run("should exclude root with invalid transition and cascade exclude children", func(t *testing.T) {
		// given — root is deactivated (cannot transition to suspended),
		// child is active + completed (would be suspendable on its own).
		// Because the parent is excluded, the child is also excluded.
		//
		//   K0 (deactivated + completed) ← excluded (deactivated → suspend is invalid)
		//     └── K1 (active + completed) ← excluded (parent excluded)
		tenant := createTenant(t, tenantStore)
		root := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K0",
			nil,
			model.KeyLifeCycleDeactivated,
			model.KeyProcessingCompleted,
		)
		rootID := root.ID
		child := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K1",
			&rootID,
			model.KeyLifeCycleActive,
			model.KeyProcessingCompleted,
		)

		// when
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
			TenantId:  tenant.ID,
			Id:        root.ID,
			Cascading: true,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)

		// verify neither key was modified
		unchangedRoot, err := keyStore.GetKeyByID(ctx, root.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleDeactivated, unchangedRoot.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedRoot.KeyProcessingState.Status)

		unchangedChild, err := keyStore.GetKeyByID(ctx, child.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, unchangedChild.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedChild.KeyProcessingState.Status)
	})

	t.Run("should suspend valid branch and ignore invalid branch with cascading", func(t *testing.T) {
		// given — root with two branches:
		//
		//              K0 (active + completed) ← suspendable
		//              /                               \
		//   K1a (active + completed)     K1b (deactivated + completed)
		//        |                                      |
		//   K2a (suspended + failed)     K2b (active + completed)
		//
		// Branch A (K1a, K2a): fully suspendable.
		// Branch B: K1b is deactivated (cannot transition to suspended),
		//   so K1b and K2b are excluded via cascading parent exclusion.
		spy := &spyJobGroupPreparer{}
		svc := keypb.NewKeyService(
			config.RootConfig{},
			storesql.NewTransactor(db),
			keyStore,
			spy,
			nil,
		)

		tenant := createTenant(t, tenantStore)

		// layer 0: root
		k0 := newTestKey(t, keyStore, tenant.ID, "K0", nil, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		k0ID := k0.ID

		// layer 1: two branches
		k1a := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		k1b := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		k1aID := k1a.ID
		k1bID := k1b.ID

		// layer 2: grandchildren
		k2a := newTestKey(t, keyStore, tenant.ID, "K2", &k1aID, model.KeyLifeCycleSuspended, model.KeyProcessingFailed)
		k2b := newTestKey(t, keyStore, tenant.ID, "K2", &k1bID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// when
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
			TenantId:  tenant.ID,
			Id:        k0.ID,
			Cascading: true,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify branch A was suspended (K0, K1a, K2a)
		updatedK0, err := keyStore.GetKeyByID(ctx, k0.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleSuspended, updatedK0.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK0.KeyProcessingState.Status)

		updatedK1a, err := keyStore.GetKeyByID(ctx, k1a.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleSuspended, updatedK1a.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK1a.KeyProcessingState.Status)

		updatedK2a, err := keyStore.GetKeyByID(ctx, k2a.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleSuspended, updatedK2a.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK2a.KeyProcessingState.Status)

		// verify branch B was not modified (K1b, K2b)
		unchangedK1b, err := keyStore.GetKeyByID(ctx, k1b.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleDeactivated, unchangedK1b.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedK1b.KeyProcessingState.Status)

		unchangedK2b, err := keyStore.GetKeyByID(ctx, k2b.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, unchangedK2b.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedK2b.KeyProcessingState.Status)

		// verify 3 jobs: layer 0 (K0), layer 1 (K1a only), layer 2 (K2a only)
		require.Len(t, spy.groups, 1)
		assert.Equal(t, suspendkey.JobGroupType, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 3)
		assert.Equal(t, suspendkey.JobType, spy.groups[0].Jobs[0].Type)
		assert.Equal(t, suspendkey.JobType, spy.groups[0].Jobs[1].Type)
		assert.Equal(t, suspendkey.JobType, spy.groups[0].Jobs[2].Type)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, k2a.ID)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[1].Data, k1a.ID)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[2].Data, k0.ID)
		for _, job := range spy.groups[0].Jobs {
			assertJobDataTenantID(t, job.Data, tenant.ID)
		}
	})

	t.Run("should suspend key and create job group", func(t *testing.T) {
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

		key := newTestKey(t, keyStore, tenant.ID, "K0", nil, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// when
		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
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
		assert.Equal(t, model.KeyLifeCycleSuspended, updatedKey.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedKey.KeyProcessingState.Status)

		// verify a job group was prepared with one job
		require.Len(t, spy.groups, 1)
		assert.Equal(t, suspendkey.JobGroupType, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 1)
		assert.Equal(t, suspendkey.JobType, spy.groups[0].Jobs[0].Type)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, key.ID)
		assertJobDataTenantID(t, spy.groups[0].Jobs[0].Data, tenant.ID)
	})

	t.Run("should suspend 2 layers out of 3 and create 2 jobs", func(t *testing.T) {
		// given
		//   K0 (active + completed) ← suspendable
		//     └── K1 (active + completed) ← suspendable
		//           └── K2 (deactivated + completed) ← excluded (cannot transition to suspended)
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
		k0 := newTestKey(t, keyStore, tenant.ID, "K0", nil, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// layer 1: child key
		k0ID := k0.ID
		k1 := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// layer 2: grandchild key — deactivated, cannot transition to suspended
		k1ID := k1.ID
		k2 := newTestKey(t, keyStore, tenant.ID, "K2", &k1ID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		res, err := svc.SuspendKey(ctx, &keypb.SuspendKeyRequest{
			TenantId:  tenant.ID,
			Id:        k0.ID,
			Cascading: true,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify K0 and K1 are suspended
		updatedK0, err := keyStore.GetKeyByID(ctx, k0.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleSuspended, updatedK0.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK0.KeyProcessingState.Status)

		updatedK1, err := keyStore.GetKeyByID(ctx, k1.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleSuspended, updatedK1.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK1.KeyProcessingState.Status)

		// verify K2 was not suspended (still deactivated)
		updatedK2, err := keyStore.GetKeyByID(ctx, k2.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleDeactivated, updatedK2.LifeCycleState)

		// verify 2 jobs were created (one per suspendable layer)
		require.Len(t, spy.groups, 1)
		assert.Equal(t, suspendkey.JobGroupType, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 2)
		assert.Equal(t, suspendkey.JobType, spy.groups[0].Jobs[0].Type)
		assert.Equal(t, suspendkey.JobType, spy.groups[0].Jobs[1].Type)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, k1.ID)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[1].Data, k0.ID)
		for _, job := range spy.groups[0].Jobs {
			assertJobDataTenantID(t, job.Data, tenant.ID)
		}
	})
}
