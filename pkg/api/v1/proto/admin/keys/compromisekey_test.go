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
	"github.com/openkcm/krypton/internal/orchestrator"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestCompromise(t *testing.T) {
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
			input *keypb.CompromiseKeyRequest
		}{
			{
				name:  "invalid uuid tenant id",
				input: &keypb.CompromiseKeyRequest{TenantId: "invalid", Id: uuid.New().String()},
			},
			{
				name:  "empty tenant id",
				input: &keypb.CompromiseKeyRequest{TenantId: "", Id: uuid.New().String()},
			},
			{
				name:  "invalid uuid key id",
				input: &keypb.CompromiseKeyRequest{TenantId: uuid.New().String(), Id: "invalid"},
			},
			{
				name:  "empty key id",
				input: &keypb.CompromiseKeyRequest{TenantId: uuid.New().String(), Id: ""},
			},
			{
				name:  "both tenant id and key id are invalid",
				input: &keypb.CompromiseKeyRequest{TenantId: "not-a-uuid", Id: "also-not-a-uuid"},
			},
		}
		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				res, err := svc.CompromiseKey(ctx, tt.input)

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
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
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
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
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
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
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
			name    string
			state   model.KeyLifeCycleState
			status  model.KeyProcessingStatus
			expCode codes.Code
		}{
			{
				name:    "preactive pending to compromised",
				state:   model.KeyLifeCyclePreActivation,
				status:  model.KeyProcessingPending,
				expCode: codes.NotFound,
			},
			{
				name:    "preactive failed to compromised",
				state:   model.KeyLifeCyclePreActivation,
				status:  model.KeyProcessingFailed,
				expCode: codes.NotFound,
			},
			{
				name:    "destroyed completed to compromised",
				state:   model.KeyLifeCycleDestroyed,
				status:  model.KeyProcessingCompleted,
				expCode: codes.NotFound,
			},
			{
				name:    "destroyed pending to compromised",
				state:   model.KeyLifeCycleDestroyed,
				status:  model.KeyProcessingPending,
				expCode: codes.NotFound,
			},
			{
				name:    "destroyed failed to compromised",
				state:   model.KeyLifeCycleDestroyed,
				status:  model.KeyProcessingFailed,
				expCode: codes.NotFound,
			},
			{
				name:    "compromised completed to compromised",
				state:   model.KeyLifeCycleCompromised,
				status:  model.KeyProcessingCompleted,
				expCode: codes.FailedPrecondition,
			},
			{
				name:    "compromised pending to compromised",
				state:   model.KeyLifeCycleCompromised,
				status:  model.KeyProcessingPending,
				expCode: codes.NotFound,
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

				// insert a key directly in a state that cannot transition to compromised
				key := newTestKey(
					t,
					keyStore,
					tenant.ID,
					"K0",
					nil,
					tt.state,
					tt.status,
				)

				// when
				res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
					TenantId: tenant.ID,
					Id:       key.ID,
				})

				// then
				require.Error(t, err)
				assert.Nil(t, res)
				assert.Equal(t, tt.expCode, status.Code(err))
				assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
			})
		}
	})

	t.Run("should compromise key and create job group", func(t *testing.T) {
		// given

		tenant := createTenant(t, tenantStore)

		tts := []struct {
			name                string
			fromState           model.KeyLifeCycleState
			fromProcessingState model.KeyProcessingStatus
		}{
			{
				name:                "from preactive and completed",
				fromState:           model.KeyLifeCyclePreActivation,
				fromProcessingState: model.KeyProcessingCompleted,
			},
			{
				name:                "from active and completed",
				fromState:           model.KeyLifeCycleActive,
				fromProcessingState: model.KeyProcessingCompleted,
			},
			{
				name:                "from deactive and completed",
				fromState:           model.KeyLifeCycleDeactivated,
				fromProcessingState: model.KeyProcessingCompleted,
			},
			{
				name:                "from deactive and pending",
				fromState:           model.KeyLifeCycleDeactivated,
				fromProcessingState: model.KeyProcessingPending,
			},
			{
				name:                "from deactive and failed",
				fromState:           model.KeyLifeCycleDeactivated,
				fromProcessingState: model.KeyProcessingFailed,
			},

			{
				name:                "from suspended and completed",
				fromState:           model.KeyLifeCycleSuspended,
				fromProcessingState: model.KeyProcessingCompleted,
			},
			{
				name:                "from suspended and pending",
				fromState:           model.KeyLifeCycleSuspended,
				fromProcessingState: model.KeyProcessingPending,
			},
			{
				name:                "from suspended and failed",
				fromState:           model.KeyLifeCycleSuspended,
				fromProcessingState: model.KeyProcessingFailed,
			},
			{
				name:                "from compromised and failed",
				fromState:           model.KeyLifeCycleCompromised,
				fromProcessingState: model.KeyProcessingFailed,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				spy := &spyJobGroupPreparer{}
				svc := keypb.NewKeyService(
					config.RootConfig{},
					storesql.NewTransactor(db),
					keyStore,
					spy,
					nil,
				)
				key := newTestKey(t, keyStore, tenant.ID, "K0", nil, tt.fromState, tt.fromProcessingState)

				// when
				res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
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
				assert.Equal(t, model.KeyLifeCycleCompromised, updatedKey.LifeCycleState)
				assert.Equal(t, model.KeyProcessingPending, updatedKey.KeyProcessingState.Status)

				// verify a job group was prepared with one job
				require.Len(t, spy.groups, 1)
				assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Type)
				require.Len(t, spy.groups[0].Jobs, 1)
				assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[0].Type)
				assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, key.ID)
				assertJobDataTenantID(t, spy.groups[0].Jobs[0].Data, tenant.ID)
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
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
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
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
			TenantId: tenant.ID,
			Id:       key.ID,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should return error if key is already compromised and completed", func(t *testing.T) {
		// given — key is already compromised + completed; no transition needed.
		tenant := createTenant(t, tenantStore)
		key := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K0",
			nil,
			model.KeyLifeCycleCompromised,
			model.KeyProcessingCompleted,
		)

		// when
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
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
		assert.Equal(t, model.KeyLifeCycleCompromised, unchanged.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchanged.KeyProcessingState.Status)
	})

	t.Run("should skip already compromised root and compromise children with cascading", func(t *testing.T) {
		// given — root is already compromised + completed, child is active + completed.
		//
		//   K0 (compromised + completed) ← skipped (already in target state)
		//     └── K1 (active + completed) ← can be compromised
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
			model.KeyLifeCycleCompromised,
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
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
			TenantId:  tenant.ID,
			Id:        root.ID,
			Cascading: true,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify root was not modified (already compromised + completed)
		unchangedRoot, err := keyStore.GetKeyByID(ctx, root.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, unchangedRoot.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedRoot.KeyProcessingState.Status)

		// verify child was compromised
		updatedChild, err := keyStore.GetKeyByID(ctx, child.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedChild.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedChild.KeyProcessingState.Status)

		// verify 1 job was created (child only, root skipped)
		require.Len(t, spy.groups, 1)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 1)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[0].Type)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, child.ID)
		assertJobDataTenantID(t, spy.groups[0].Jobs[0].Data, tenant.ID)
	})

	t.Run("should exclude root with invalid transition and cascade exclude children", func(t *testing.T) {
		// given — root is preactive failed (cannot transition to compromised),
		// child is active + completed (would be compromised on its own).
		// Because the parent is excluded, the child is also excluded.
		//
		//   K0 (preactive + failed) ← excluded (preactive + failed does not match any filter)
		//     └── K1 (active + completed) ← excluded (parent excluded)
		tenant := createTenant(t, tenantStore)
		root := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K0",
			nil,
			model.KeyLifeCyclePreActivation,
			model.KeyProcessingFailed,
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
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
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
		assert.Equal(t, model.KeyLifeCyclePreActivation, unchangedRoot.LifeCycleState)
		assert.Equal(t, model.KeyProcessingFailed, unchangedRoot.KeyProcessingState.Status)

		unchangedChild, err := keyStore.GetKeyByID(ctx, child.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, unchangedChild.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedChild.KeyProcessingState.Status)
	})

	t.Run("should compromise valid branch and ignore invalid branch with cascading", func(t *testing.T) {
		// given — root with two branches:
		//
		//              K0 (active + completed)             ← compromiseable
		//              /                               \
		//   K1a (deactivated + failed)     K1b (preactive + failed)
		//        |                                      |
		//   K2a (suspended + completed)     K2b (preactive + failed)
		//
		// Branch A (K1a, K2a): fully compromisable.
		// Branch B: K1b is preactive+failed (cannot transition to compromise),
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
		k1a := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleDeactivated, model.KeyProcessingFailed)
		k1b := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCyclePreActivation, model.KeyProcessingFailed)
		k1aID := k1a.ID
		k1bID := k1b.ID

		// layer 2: grandchildren
		k2a := newTestKey(t, keyStore, tenant.ID, "K2", &k1aID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		k2b := newTestKey(t, keyStore, tenant.ID, "K2", &k1bID, model.KeyLifeCyclePreActivation, model.KeyProcessingFailed)

		// when
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
			TenantId:  tenant.ID,
			Id:        k0.ID,
			Cascading: true,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify branch A was compromised (K0, K1a, K2a)
		updatedK0, err := keyStore.GetKeyByID(ctx, k0.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedK0.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK0.KeyProcessingState.Status)

		updatedK1a, err := keyStore.GetKeyByID(ctx, k1a.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedK1a.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK1a.KeyProcessingState.Status)

		updatedK2a, err := keyStore.GetKeyByID(ctx, k2a.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedK2a.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK2a.KeyProcessingState.Status)

		// verify branch B was not modified (K1b, K2b)
		unchangedK1b, err := keyStore.GetKeyByID(ctx, k1b.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCyclePreActivation, unchangedK1b.LifeCycleState)
		assert.Equal(t, model.KeyProcessingFailed, unchangedK1b.KeyProcessingState.Status)

		unchangedK2b, err := keyStore.GetKeyByID(ctx, k2b.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCyclePreActivation, unchangedK2b.LifeCycleState)
		assert.Equal(t, model.KeyProcessingFailed, unchangedK2b.KeyProcessingState.Status)

		// verify 3 jobs: layer 0 (K0), layer 1 (K1a only), layer 2 (K2a only)
		require.Len(t, spy.groups, 1)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 3)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[0].Type)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[1].Type)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[2].Type)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, k2a.ID)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[1].Data, k1a.ID)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[2].Data, k0.ID)
		for _, job := range spy.groups[0].Jobs {
			assertJobDataTenantID(t, job.Data, tenant.ID)
		}
	})

	t.Run("should compromise 2 layers out of 3 and create 2 jobs", func(t *testing.T) {
		// given
		//   K0 (active + completed) ← compromiseable
		//     └── K1 (suspended + completed) ← compromiseable
		//           └── K2 (preactive + failed) ← excluded (cannot transition to compromise)
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
		k1 := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

		// layer 2: grandchild key — preactive, cannot transition to compromise
		k1ID := k1.ID
		k2 := newTestKey(t, keyStore, tenant.ID, "K2", &k1ID, model.KeyLifeCyclePreActivation, model.KeyProcessingFailed)

		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
			TenantId:  tenant.ID,
			Id:        k0.ID,
			Cascading: true,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify K0 and K1 are compromised
		updatedK0, err := keyStore.GetKeyByID(ctx, k0.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedK0.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK0.KeyProcessingState.Status)

		updatedK1, err := keyStore.GetKeyByID(ctx, k1.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedK1.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK1.KeyProcessingState.Status)

		// verify K2 was not compromised (still preactive+failed)
		updatedK2, err := keyStore.GetKeyByID(ctx, k2.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCyclePreActivation, updatedK2.LifeCycleState)

		// verify 2 jobs were created (one per compromisable layer)
		require.Len(t, spy.groups, 1)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 2)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[0].Type)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[1].Type)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, k1.ID)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[1].Data, k0.ID)
		for _, job := range spy.groups[0].Jobs {
			assertJobDataTenantID(t, job.Data, tenant.ID)
		}
	})

	t.Run("should ignore compromised and completed keys in the tree path", func(t *testing.T) {
		// given
		//   K0 (active + completed) ← compromisable
		//     └── K1 (compromised + completed) ← should ignore this
		//           └── K2 (suspended + completed) ← should not ignore this
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
		k1 := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		// layer 2: grandchild key — suspended, can transition to compromised
		k1ID := k1.ID
		k2 := newTestKey(t, keyStore, tenant.ID, "K2", &k1ID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
			TenantId:  tenant.ID,
			Id:        k0.ID,
			Cascading: true,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify K0 and K1 are compromised
		updatedK0, err := keyStore.GetKeyByID(ctx, k0.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedK0.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK0.KeyProcessingState.Status)

		updatedK1, err := keyStore.GetKeyByID(ctx, k1.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedK1.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, updatedK1.KeyProcessingState.Status)

		// verify K2 was compromised
		updatedK2, err := keyStore.GetKeyByID(ctx, k2.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedK2.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedK2.KeyProcessingState.Status)

		// verify 2 jobs were created (one per compromised layer)
		require.Len(t, spy.groups, 1)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 2)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[0].Type)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Jobs[1].Type)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, k2.ID)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[1].Data, k0.ID)
		for _, job := range spy.groups[0].Jobs {
			assertJobDataTenantID(t, job.Data, tenant.ID)
		}
	})

	t.Run("should return error if all descendants are already compromised and completed with cascading", func(t *testing.T) {
		// given — entire tree is already at the target state (compromised + completed).
		// All keys are skipped during iteration → ErrNoEligibleKeys → FailedPrecondition.
		//
		//   K0 (compromised + completed) ← skipped
		//     └── K1 (compromised + completed) ← skipped
		tenant := createTenant(t, tenantStore)
		root := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K0",
			nil,
			model.KeyLifeCycleCompromised,
			model.KeyProcessingCompleted,
		)
		rootID := root.ID
		child := newTestKey(
			t,
			keyStore,
			tenant.ID,
			"K1",
			&rootID,
			model.KeyLifeCycleCompromised,
			model.KeyProcessingCompleted,
		)

		// when
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
			TenantId:  tenant.ID,
			Id:        root.ID,
			Cascading: true,
		})

		// then
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)

		// verify neither key was modified
		unchangedRoot, err := keyStore.GetKeyByID(ctx, root.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, unchangedRoot.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedRoot.KeyProcessingState.Status)

		unchangedChild, err := keyStore.GetKeyByID(ctx, child.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, unchangedChild.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedChild.KeyProcessingState.Status)
	})

	t.Run("should not compromise children when cascading is false", func(t *testing.T) {
		// given — root is active + completed, child is active + completed.
		// Only the root should be compromised; the child must remain untouched.
		//
		//   K0 (active + completed) ← compromised
		//     └── K1 (active + completed) ← should remain active
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
			model.KeyLifeCycleActive,
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
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
			TenantId: tenant.ID,
			Id:       root.ID,
			// Cascading is false (default)
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify root was compromised
		updatedRoot, err := keyStore.GetKeyByID(ctx, root.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleCompromised, updatedRoot.LifeCycleState)
		assert.Equal(t, model.KeyProcessingPending, updatedRoot.KeyProcessingState.Status)

		// verify child was NOT compromised
		unchangedChild, err := keyStore.GetKeyByID(ctx, child.ID, tenant.ID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, unchangedChild.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, unchangedChild.KeyProcessingState.Status)

		// verify only 1 job was created for the root
		require.Len(t, spy.groups, 1)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 1)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, root.ID)
		assertJobDataTenantID(t, spy.groups[0].Jobs[0].Data, tenant.ID)
	})

	t.Run("should compromise multiple siblings in same layer into a single job with cascading", func(t *testing.T) {
		// given — root with three eligible children at the same layer.
		// All children should appear in a single job; root in another.
		//
		//            K0 (active + completed)
		//          /          |            \
		//   K1a (active)  K1b (suspended)  K1c (active)   ← all completed, all eligible
		//
		// Bottom-up: job[0] = [K1a, K1b, K1c], job[1] = [K0]
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

		// layer 1: three siblings
		k1a := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		k1b := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		k1c := newTestKey(t, keyStore, tenant.ID, "K1", &k0ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// when
		res, err := svc.CompromiseKey(ctx, &keypb.CompromiseKeyRequest{
			TenantId:  tenant.ID,
			Id:        k0.ID,
			Cascading: true,
		})

		// then
		require.NoError(t, err)
		require.NotNil(t, res)
		assert.NotEmpty(t, res.GetJobGroupId())

		// verify all keys were compromised
		for _, key := range []model.Key{k0, k1a, k1b, k1c} {
			updated, err := keyStore.GetKeyByID(ctx, key.ID, tenant.ID)
			require.NoError(t, err)
			assert.Equal(t, model.KeyLifeCycleCompromised, updated.LifeCycleState, "key %s should be compromised", key.ID)
			assert.Equal(t, model.KeyProcessingPending, updated.KeyProcessingState.Status, "key %s should be pending", key.ID)
		}

		// verify 2 jobs: job[0] = siblings (bottom-up), job[1] = root
		require.Len(t, spy.groups, 1)
		assert.Equal(t, orchestrator.CompromiseKey, spy.groups[0].Type)
		require.Len(t, spy.groups[0].Jobs, 2)

		// job[0] should contain all three siblings (order-independent)
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[0].Data, k1a.ID, k1b.ID, k1c.ID)

		// job[1] should contain the root
		assertJobDataContainsKeys(t, spy.groups[0].Jobs[1].Data, k0.ID)

		for _, job := range spy.groups[0].Jobs {
			assertJobDataTenantID(t, job.Data, tenant.ID)
		}
	})
}
