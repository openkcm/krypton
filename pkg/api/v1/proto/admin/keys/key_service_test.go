package keys_test

import (
	"context"
	"errors"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// errJobPreparer is a JobPreparer stub that always returns the configured
// error. Used to simulate concurrent-race / failure paths from PrepareJob.
type errJobPreparer struct {
	err error
}

func (e errJobPreparer) PrepareJob(_ context.Context, job orbital.Job) (orbital.Job, error) {
	return job, e.err
}

// keyHierarchy holds a test key tree with the following structure:
//
//	A(K0)
//	  B(K1)
//	    D(K2)
//	    E(K2)
//	  C(K1)
//	    F(K2)
//	    G(K2)
//	      H(K3)
type keyHierarchy struct {
	tenant model.Tenant
	root   model.Key // A
	b      model.Key
	c      model.Key
	d      model.Key
	e      model.Key
	f      model.Key
	g      model.Key
	h      model.Key
}

// activateKey flips a freshly-announced key into Active so it can serve as a
// parent in subsequent AnnounceKey calls (per the strict "parent must be
// Active" rule enforced in KeyService.AnnounceKey).
func activateKey(t *testing.T, ks store.Key, id, tenantID string) {
	t.Helper()
	require.NoError(t, ks.UpdateKeyLifeCycleState(t.Context(), store.UpdateKeyLifeCycleStateQuery{
		ID:       id,
		TenantID: tenantID,
		NewState: model.KeyLifeCycleActive,
	}))
}

func TestAnnounceKey(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))

	t.Run("should create key successfully", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		// when
		res, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.New().String(),
			TargetName: "",
			Labels:     map[string]string{"env": "prod"},
		})

		// then
		assert.NoError(t, err)
		assert.NotEmpty(t, res.GetKey().GetId())
		assert.Equal(t, "K0", res.GetKey().GetKind())
		assert.Equal(t, "root", res.GetKey().GetManagedBy())
		assert.Equal(t, "pre-activation", res.GetKey().GetLifeCycleState())
		// Root-managed keys do not need a job — persisted as Completed immediately.
		assert.Equal(t, string(model.KeyProcessingCompleted), res.GetKey().GetKeyProcessingState().GetStatus())
		assert.Empty(t, res.GetKey().GetKeyProcessingState().GetJobId())
		assert.Equal(t, tenant.ID, res.GetKey().GetTenantId())
		assert.Equal(t, "prod", res.GetKey().GetLabels()["env"])
		assert.NotZero(t, res.GetKey().GetCreatedAt())
		assert.NotZero(t, res.GetKey().GetUpdatedAt())
	})

	t.Run("should be idempotent on duplicate (tenant, name)", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		name := "idempotent-" + uuid.New().String()
		first, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       name,
			TargetName: "",
		})
		require.NoError(t, err)
		require.NotEmpty(t, first.GetKey().GetId())

		second, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       name,
			TargetName: "",
		})
		require.NoError(t, err)

		assert.Equal(t, first.GetKey().GetId(), second.GetKey().GetId())
		assert.Equal(t, first.GetKey().GetKeyProcessingState().GetStatus(), second.GetKey().GetKeyProcessingState().GetStatus())
	})

	t.Run("should succeed when orbital reports job already exists for fresh key", func(t *testing.T) {
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), errJobPreparer{err: orbital.ErrJobAlreadyExists}, nil)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// Pre-seed the key so the lookup-by-name fallback (after orbital
		// dedupe) finds it.
		name := "racer-" + uuid.New().String()
		seed := model.NewKey(tenant.ID, name, "K0", nil, "root", nil)
		seed.KeyProcessingState = model.KeyProcessingState{
			Status: model.KeyProcessingInProgress,
			JobID:  uuid.New().String(),
		}
		require.NoError(t, keyStore.CreateKey(ctx, seed))

		// Subsequent call short-circuits via existing in-progress key,
		// without ever needing PrepareJob.
		resp, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       name,
			TargetName: "",
		})
		require.NoError(t, err)
		assert.Equal(t, seed.ID, resp.GetKey().GetId())
	})

	t.Run("should surface RETRY on other PrepareJob errors", func(t *testing.T) {
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), errJobPreparer{err: errors.New("boom")}, nil)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// PrepareJob is only called for non-root-managed keys, so seed an
		// Active K0 parent and announce a K1 against the agent target.
		parent := model.NewKey(tenant.ID, "boom-parent-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, parent))
		activateKey(t, keyStore, parent.ID, tenant.ID)

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "boom-" + uuid.New().String(),
			ParentId:   parent.ID,
			TargetName: "agent",
		})
		require.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should create key with parent", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		parentRes, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "parent-" + uuid.New().String(),
			TargetName: "",
		})
		require.NoError(t, err)
		// Parent must be Active to be usable as a parent.
		activateKey(t, keyStore, parentRes.GetKey().GetId(), tenant.ID)

		// when
		res, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "child-" + uuid.New().String(),
			ParentId:   parentRes.GetKey().GetId(),
			TargetName: "agent",
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, parentRes.GetKey().GetId(), res.GetKey().GetParentId())
		assert.Equal(t, "agent", res.GetKey().GetManagedBy())
	})

	t.Run("should reject when tenant does not exist", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   uuid.New().String(),
			Kind:       "K0",
			Name:       "no-tenant-" + uuid.New().String(),
			TargetName: "",
		})
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should reject when kind is not in hierarchy", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "KX",
			Name:       "bad-kind-" + uuid.New().String(),
			TargetName: "",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should reject non-root kind without parent", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "rootless-child-" + uuid.New().String(),
			TargetName: "agent",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should reject root kind with parent", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// Pre-seed an Active K0 to use as the (illegal) parent.
		other := model.NewKey(tenant.ID, "other-root-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, other))
		activateKey(t, keyStore, other.ID, tenant.ID)

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "rooted-root-" + uuid.New().String(),
			ParentId:   other.ID,
			TargetName: "",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should reject when parent does not exist in tenant", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "missing-parent-" + uuid.New().String(),
			ParentId:   uuid.New().String(),
			TargetName: "agent",
		})
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should reject when parent is not active", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// Pre-seed a K0 without activating it.
		parent := model.NewKey(tenant.ID, "inactive-parent-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, parent))

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       "child-of-inactive-" + uuid.New().String(),
			ParentId:   parent.ID,
			TargetName: "agent",
		})
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should reject when child kind is not adjacent to parent kind", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// Pre-seed an Active K0; try announcing K2 directly under it (skipping K1).
		parent := model.NewKey(tenant.ID, "skip-parent-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, parent))
		activateKey(t, keyStore, parent.ID, tenant.ID)

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K2",
			Name:       "skip-child-" + uuid.New().String(),
			ParentId:   parent.ID,
			TargetName: "agent",
		})
		require.Error(t, err)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should retry by preparing a new job when previous job failed", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// Pre-seed a key already in Failed state from a prior attempt.
		failedJobID := uuid.New().String()
		key := model.NewKey(tenant.ID, "retry-me-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))
		require.NoError(t, keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingFailed,
			NewJobID:  failedJobID,
		}))

		resp, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       key.Name,
			TargetName: "",
		})
		require.NoError(t, err)
		assert.Equal(t, key.ID, resp.GetKey().GetId(), "retry must reuse the existing key.ID")
		assert.Equal(t, string(model.KeyProcessingPending), resp.GetKey().GetKeyProcessingState().GetStatus())
		assert.NotEmpty(t, resp.GetKey().GetKeyProcessingState().GetJobId())
		assert.NotEqual(t, failedJobID, resp.GetKey().GetKeyProcessingState().GetJobId(), "retry must produce a new job ID")

		// And the linkage on disk reflects the new pending JobID.
		stored, err := keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingPending, stored.KeyProcessingState.Status)
		assert.Equal(t, resp.GetKey().GetKeyProcessingState().GetJobId(), stored.KeyProcessingState.JobID)
	})

	t.Run("ExternalID is key.ID for fresh agent-managed creation", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, nil)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// Seed an Active K0 parent so the agent-managed K1 announce passes validation.
		parent := model.NewKey(tenant.ID, "spy-parent-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, parent))
		activateKey(t, keyStore, parent.ID, tenant.ID)

		name := "spy-fresh-" + uuid.New().String()
		resp, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       name,
			ParentId:   parent.ID,
			TargetName: "agent",
		})
		require.NoError(t, err)

		require.Len(t, spy.jobs, 1)
		assert.Equal(t, resp.GetKey().GetId(), spy.jobs[0].ExternalID,
			"fresh-create ExternalID must equal the new key.ID for orbital dedup")
	})

	t.Run("root-managed fresh creation does not call PrepareJob", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, nil)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		resp, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "root-no-job-" + uuid.New().String(),
			TargetName: "",
		})
		require.NoError(t, err)
		assert.Empty(t, spy.jobs, "root-managed announce must not enqueue a job")
		assert.Equal(t, string(model.KeyProcessingCompleted), resp.GetKey().GetKeyProcessingState().GetStatus())
		assert.Empty(t, resp.GetKey().GetKeyProcessingState().GetJobId())
	})

	t.Run("ExternalID is key.ID for failed retry (no suffix)", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, nil)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		failedJobID := uuid.New().String()
		key := model.NewKey(tenant.ID, "spy-retry-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))
		require.NoError(t, keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingFailed,
			NewJobID:  failedJobID,
		}))

		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       key.Name,
			TargetName: "",
		})
		require.NoError(t, err)

		require.Len(t, spy.jobs, 1)
		assert.Equal(t, key.ID, spy.jobs[0].ExternalID,
			"retry ExternalID must equal key.ID — orbital dedup permits re-use after a terminal-state job")
	})

	t.Run("retries when existing key is Pending", func(t *testing.T) {
		spy := &spyJobPreparer{}
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), spy, nil)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// A key in Pending state (CreateKey succeeded but linkage write didn't,
		// or the key was created by some other path) should be retried as a
		// fresh job with ExternalID = key.ID — no :retry: suffix because there
		// is no previous failed JobID to scope against.
		key := model.NewKey(tenant.ID, "pending-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))

		resp, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       key.Name,
			TargetName: "",
		})
		require.NoError(t, err)

		assert.Equal(t, key.ID, resp.GetKey().GetId(), "pending re-attempt must reuse the existing key.ID")
		assert.Equal(t, string(model.KeyProcessingPending), resp.GetKey().GetKeyProcessingState().GetStatus())
		assert.NotEmpty(t, resp.GetKey().GetKeyProcessingState().GetJobId())

		require.Len(t, spy.jobs, 1)
		assert.Equal(t, key.ID, spy.jobs[0].ExternalID,
			"pending retry ExternalID must equal key.ID")

		// Linkage on disk reflects the new pending JobID; ConfirmJob is what flips Pending→InProgress.
		stored, err := keyStore.GetKeyByID(ctx, key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingPending, stored.KeyProcessingState.Status)
		assert.Equal(t, resp.GetKey().GetKeyProcessingState().GetJobId(), stored.KeyProcessingState.JobID)
	})

	t.Run("concurrent retry collides on deterministic ExternalID", func(t *testing.T) {
		setup := setupKeyServerAndClientWith(t, db, defaultTestHierarchy(), errJobPreparer{err: orbital.ErrJobAlreadyExists}, nil)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// Two simultaneous retries for the same Failed key compute the same
		// ExternalID and the second PrepareJob should return ErrJobAlreadyExists,
		// which the service swallows and returns the existing key.
		failedJobID := uuid.New().String()
		key := model.NewKey(tenant.ID, "racy-retry-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, key))
		require.NoError(t, keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingFailed,
			NewJobID:  failedJobID,
		}))

		resp, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       key.Name,
			TargetName: "",
		})
		require.NoError(t, err)
		assert.Equal(t, key.ID, resp.GetKey().GetId())
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)
		require.NoError(t, storesql.Migrate(ctx, tmpDB))

		setup := setupKeyServerAndClient(t, tmpDB)
		cli := setup.cli

		// Seed a tenant in the temp DB so tenant-existence passes; then drop
		// the keys table so the downstream lookup fails.
		tmpTenant := createTenant(t, setup.tenantStore)
		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys CASCADE")
		require.NoError(t, err)

		// when
		resp, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tmpTenant.ID,
			Kind:       "K0",
			Name:       "will-fail",
			TargetName: "",
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})

	t.Run("should reject conflicting key with same name but different parent", func(t *testing.T) {
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		keyStore := setup.keyStore
		tenant := createTenant(t, setup.tenantStore)

		// Seed two distinct active K0 parents under this tenant.
		parentA := model.NewKey(tenant.ID, "conflict-parent-a-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, parentA))
		activateKey(t, keyStore, parentA.ID, tenant.ID)

		parentB := model.NewKey(tenant.ID, "conflict-parent-b-"+uuid.New().String(), "K0", nil, "root", nil)
		require.NoError(t, keyStore.CreateKey(ctx, parentB))
		activateKey(t, keyStore, parentB.ID, tenant.ID)

		name := "conflicting-child-" + uuid.New().String()
		// First announce binds (tenant, name) to parentA.
		_, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       name,
			ParentId:   parentA.ID,
			TargetName: "agent",
		})
		require.NoError(t, err)

		// Re-announcing the same name with a different parent must surface
		// FailedPrecondition + ABORT (conflicting values).
		_, err = cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K1",
			Name:       name,
			ParentId:   parentB.ID,
			TargetName: "agent",
		})
		require.Error(t, err)
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})
}

func TestGetKeyService(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))

	t.Run("should get key successfully", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		// when
		created, err := cli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenant.ID,
			Kind:       "K0",
			Name:       "get-me-" + uuid.New().String(),
			TargetName: "",
			Labels:     map[string]string{"env": "staging"},
		})

		// then
		require.NoError(t, err)

		res, err := cli.GetKey(ctx, &keypb.GetKeyRequest{
			Id:       created.GetKey().GetId(),
			TenantId: tenant.ID,
		})

		assert.NoError(t, err)
		assert.Equal(t, created.GetKey().GetId(), res.GetKey().GetId())
		assert.Equal(t, created.GetKey().GetName(), res.GetKey().GetName())
		assert.Equal(t, "staging", res.GetKey().GetLabels()["env"])
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		// given
		setup := setupKeyServerAndClient(t, db)
		cli := setup.cli
		tenant := createTenant(t, setup.tenantStore)

		// when
		resp, err := cli.GetKey(ctx, &keypb.GetKeyRequest{
			Id:       uuid.New().String(),
			TenantId: tenant.ID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys CASCADE")
		require.NoError(t, err)

		setup := setupKeyServerAndClient(t, tmpDB)
		cli := setup.cli

		// when
		resp, err := cli.GetKey(ctx, &keypb.GetKeyRequest{
			Id:       uuid.New().String(),
			TenantId: uuid.New().String(),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}

func TestGetParentKeys(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)

	require.NoError(t, storesql.Migrate(ctx, db))

	setup := setupKeyServerAndClient(t, db)
	cli := setup.cli
	keyStore := setup.keyStore
	tenant := createTenant(t, setup.tenantStore)

	ha := createKeyHierarchy(t, keyStore, tenant)

	t.Run("should get parent keys successfully for intermediate", func(t *testing.T) {
		// when
		res, err := cli.GetParentKeys(ctx, &keypb.GetParentKeysRequest{
			Id:       ha.g.ID,
			TenantId: tenant.ID,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, res.GetKeys(), 3)
		assert.Equal(t, ha.root.ID, res.GetKeys()[0].GetId())
		assert.Equal(t, ha.c.ID, res.GetKeys()[1].GetId())
		assert.Equal(t, ha.g.ID, res.GetKeys()[2].GetId())
	})

	t.Run("should get parent keys successfully for leaf node", func(t *testing.T) {
		// when
		res, err := cli.GetParentKeys(ctx, &keypb.GetParentKeysRequest{
			Id:       ha.h.ID,
			TenantId: tenant.ID,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, res.GetKeys(), 4)
		assert.Equal(t, ha.root.ID, res.GetKeys()[0].GetId())
		assert.Equal(t, ha.c.ID, res.GetKeys()[1].GetId())
		assert.Equal(t, ha.g.ID, res.GetKeys()[2].GetId())
		assert.Equal(t, ha.h.ID, res.GetKeys()[3].GetId())
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		// when
		res, err := cli.GetParentKeys(ctx, &keypb.GetParentKeysRequest{
			Id:       uuid.New().String(),
			TenantId: tenant.ID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys CASCADE")
		require.NoError(t, err)

		setup := setupKeyServerAndClient(t, tmpDB)
		cli := setup.cli

		// when
		resp, err := cli.GetParentKeys(ctx, &keypb.GetParentKeysRequest{
			Id:       uuid.New().String(),
			TenantId: uuid.New().String(),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}

func TestGetDescendantKeys(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(ctx, db))

	setup := setupKeyServerAndClient(t, db)
	cli := setup.cli
	keyStore := setup.keyStore
	tenant := createTenant(t, setup.tenantStore)

	ha := createKeyHierarchy(t, keyStore, tenant)

	t.Run("should get descendant keys successfully for root", func(t *testing.T) {
		// when
		res, err := cli.GetDescendantKeys(ctx, &keypb.GetDescendantKeysRequest{
			Id:       ha.root.ID,
			TenantId: tenant.ID,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, res.GetKeyTree(), 4)                                    // 4 levels in the tree
		assert.Len(t, res.GetKeyTree()[0].GetKeys(), 1)                       // root level
		assert.Equal(t, ha.root.ID, res.GetKeyTree()[0].GetKeys()[0].GetId()) // root key

		assert.Len(t, res.GetKeyTree()[1].GetKeys(), 2)                    // level 1 has 2 keys: B and C
		assert.Equal(t, ha.b.ID, res.GetKeyTree()[1].GetKeys()[0].GetId()) // B key
		assert.Equal(t, ha.c.ID, res.GetKeyTree()[1].GetKeys()[1].GetId()) // C key

		assert.Len(t, res.GetKeyTree()[2].GetKeys(), 4)                    // level 2 has 4 keys: D, E, F, G
		assert.Equal(t, ha.d.ID, res.GetKeyTree()[2].GetKeys()[0].GetId()) // D key
		assert.Equal(t, ha.e.ID, res.GetKeyTree()[2].GetKeys()[1].GetId()) // E key
		assert.Equal(t, ha.f.ID, res.GetKeyTree()[2].GetKeys()[2].GetId()) // F key
		assert.Equal(t, ha.g.ID, res.GetKeyTree()[2].GetKeys()[3].GetId()) // G key

		assert.Len(t, res.GetKeyTree()[3].GetKeys(), 1)                    // level 3 has 1 key: H
		assert.Equal(t, ha.h.ID, res.GetKeyTree()[3].GetKeys()[0].GetId()) // H key
	})

	t.Run("should get descendant keys successfully for intermediate", func(t *testing.T) {
		// when
		res, err := cli.GetDescendantKeys(ctx, &keypb.GetDescendantKeysRequest{
			Id:       ha.c.ID,
			TenantId: tenant.ID,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, res.GetKeyTree(), 3)

		assert.Len(t, res.GetKeyTree()[0].GetKeys(), 1)
		assert.Equal(t, ha.c.ID, res.GetKeyTree()[0].GetKeys()[0].GetId())

		assert.Len(t, res.GetKeyTree()[1].GetKeys(), 2)
		assert.Equal(t, ha.f.ID, res.GetKeyTree()[1].GetKeys()[0].GetId())
		assert.Equal(t, ha.g.ID, res.GetKeyTree()[1].GetKeys()[1].GetId())

		assert.Len(t, res.GetKeyTree()[2].GetKeys(), 1)
		assert.Equal(t, ha.h.ID, res.GetKeyTree()[2].GetKeys()[0].GetId())
	})

	t.Run("should get descendant successfully for leaf node", func(t *testing.T) {
		// when
		res, err := cli.GetDescendantKeys(ctx, &keypb.GetDescendantKeysRequest{
			Id:       ha.h.ID,
			TenantId: tenant.ID,
		})

		// then
		assert.NoError(t, err)
		assert.Len(t, res.GetKeyTree(), 1)

		assert.Len(t, res.GetKeyTree()[0].GetKeys(), 1)
		assert.Equal(t, ha.h.ID, res.GetKeyTree()[0].GetKeys()[0].GetId())
	})

	t.Run("should return not found for nonexistent key", func(t *testing.T) {
		// when
		res, err := cli.GetDescendantKeys(ctx, &keypb.GetDescendantKeysRequest{
			Id:       uuid.New().String(),
			TenantId: tenant.ID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys CASCADE")
		require.NoError(t, err)

		setup := setupKeyServerAndClient(t, tmpDB)
		cli := setup.cli

		// when
		resp, err := cli.GetDescendantKeys(ctx, &keypb.GetDescendantKeysRequest{
			Id:       uuid.New().String(),
			TenantId: uuid.New().String(),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}

func TestListKeys(t *testing.T) {
	// given
	ctx := t.Context()
	db := createDatabase(t)
	require.NoError(t, storesql.Migrate(ctx, db))

	setup := setupKeyServerAndClient(t, db)
	cli := setup.cli
	keyStore := setup.keyStore
	tenant := createTenant(t, setup.tenantStore)

	ha := createKeyHierarchy(t, keyStore, tenant)

	t.Run("should return all keys for a tenantID", func(t *testing.T) {
		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId: ha.tenant.ID,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res.GetKeys(), 8)
		assert.Empty(t, res.GetCursor())
	})

	t.Run("should return keys filtered by kind", func(t *testing.T) {
		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId: ha.tenant.ID,
			Kind:     "K2",
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res.GetKeys(), 4)
		assert.Equal(t, ha.d.ID, res.GetKeys()[3].GetId())
		assert.Equal(t, ha.e.ID, res.GetKeys()[2].GetId())
		assert.Equal(t, ha.f.ID, res.GetKeys()[1].GetId())
		assert.Equal(t, ha.g.ID, res.GetKeys()[0].GetId())
		assert.Empty(t, res.GetCursor())
	})

	t.Run("should return keys filtered by managed by", func(t *testing.T) {
		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId:  ha.tenant.ID,
			ManagedBy: ha.d.ManagedBy,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res.GetKeys(), 1)
		assert.Equal(t, ha.d.ID, res.GetKeys()[0].GetId())
		assert.Empty(t, res.GetCursor())
	})

	t.Run("should return keys filtered by name", func(t *testing.T) {
		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId: ha.tenant.ID,
			Name:     ha.c.Name,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res.GetKeys(), 1)
		assert.Equal(t, ha.c.ID, res.GetKeys()[0].GetId())
		assert.Empty(t, res.GetCursor())
	})

	t.Run("should return keys filtered by life cycle state", func(t *testing.T) {
		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId:       ha.tenant.ID,
			LifeCycleState: string(ha.g.LifeCycleState),
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res.GetKeys(), 1)
		assert.Equal(t, ha.g.ID, res.GetKeys()[0].GetId())
		assert.Empty(t, res.GetCursor())
	})

	t.Run("should return keys filtered by labels", func(t *testing.T) {
		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId: ha.tenant.ID,
			Labels:   ha.e.Labels,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res.GetKeys(), 1)
		assert.Equal(t, ha.e.ID, res.GetKeys()[0].GetId())
		assert.Empty(t, res.GetCursor())
	})

	t.Run("should paginate with limit and return cursor in descending order", func(t *testing.T) {
		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId: ha.tenant.ID,
			Limit:    1,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res.GetKeys(), 1)
		assert.Equal(t, ha.h.ID, res.GetKeys()[0].GetId())
		assert.NotEmpty(t, res.GetCursor())
	})

	t.Run("should paginate with limit and return cursor in ascending order", func(t *testing.T) {
		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId:              ha.tenant.ID,
			Limit:                 1,
			IsOrderByCreatedAtAsc: true,
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, res)
		assert.Len(t, res.GetKeys(), 1)
		assert.Equal(t, ha.root.ID, res.GetKeys()[0].GetId())
		assert.NotEmpty(t, res.GetCursor())
	})

	t.Run("should return key not found error for an unknown tenantID", func(t *testing.T) {
		// given
		unknownTenantID := uuid.New().String()

		// when
		res, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId: unknownTenantID,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, res)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
	})

	t.Run("should return internal error on database failure", func(t *testing.T) {
		// given
		tmpDB := createDatabase(t)

		require.NoError(t, storesql.Migrate(ctx, tmpDB))

		_, err := tmpDB.ExecContext(ctx, "DROP TABLE keys CASCADE")
		require.NoError(t, err)

		setup := setupKeyServerAndClient(t, tmpDB)
		cli := setup.cli

		// when
		resp, err := cli.ListKeys(ctx, &keypb.ListKeysRequest{
			TenantId: uuid.New().String(),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
		assert.Equal(t, codes.Internal, status.Code(err))
		assertErrorDetails(t, proto.Code_ERROR_CODE_RETRY, err)
	})
}

// createKeyHierarchy sets up a test key hierarchy with 8 keys across 4 levels and returns the created keys for reference in tests.
// keyHierarchy holds a test key tree with the following structure:
//
//	A(K0)
//	  B(K1)
//	    D(K2)
//	    E(K2)
//	  C(K1)
//	    F(K2)
//	    G(K2)
//	      H(K3)
func createKeyHierarchy(t *testing.T, keyStore store.Key, tenant model.Tenant) keyHierarchy {
	t.Helper()
	ctx := t.Context()

	root := model.NewKey(tenant.ID, "A", "K0", nil, "root", nil)
	err := keyStore.CreateKey(ctx, root)
	require.NoError(t, err)

	b := model.NewKey(tenant.ID, "B", "K1", &root.ID, "root", nil)
	err = keyStore.CreateKey(ctx, b)
	require.NoError(t, err)

	c := model.NewKey(tenant.ID, "C", "K1", &root.ID, "root", model.Labels{
		"env": "staging",
	})
	err = keyStore.CreateKey(ctx, c)
	require.NoError(t, err)

	d := model.NewKey(tenant.ID, "D", "K2", &b.ID, "agent-aws", nil)
	err = keyStore.CreateKey(ctx, d)
	require.NoError(t, err)

	e := model.NewKey(tenant.ID, "E", "K2", &b.ID, "agent-azure", model.Labels{
		"env": "prod",
	})
	err = keyStore.CreateKey(ctx, e)
	require.NoError(t, err)

	f := model.NewKey(tenant.ID, "F", "K2", &c.ID, "agent-gcp", nil)
	err = keyStore.CreateKey(ctx, f)
	require.NoError(t, err)

	g := model.NewKey(tenant.ID, "G", "K2", &c.ID, "agent-onprem", nil)
	g.LifeCycleState = model.KeyLifeCycleCompromised
	err = keyStore.CreateKey(ctx, g)
	require.NoError(t, err)

	h := model.NewKey(tenant.ID, "H", "K3", &g.ID, "agent-onprem-2", nil)
	err = keyStore.CreateKey(ctx, h)
	require.NoError(t, err)

	return keyHierarchy{
		tenant: tenant,
		root:   root,
		b:      b,
		c:      c,
		d:      d,
		e:      e,
		f:      f,
		g:      g,
		h:      h,
	}
}
