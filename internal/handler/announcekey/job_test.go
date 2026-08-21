package announcekey_test

import (
	"encoding/json/v2"
	"errors"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	guuid "github.com/google/uuid"

	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
	"github.com/openkcm/krypton/pkg/validator"
)

func TestJobHandler_OnJobFailed(t *testing.T) {
	t.Run("should mark processing state failed", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)

		handler := announcekey.NewJobHandler(keyStore, passingValidator())
		jobID := guuid.UUID(uuid.NewV7())

		data := announcekey.TaskData{
			KeyID:    key.ID,
			TenantID: key.TenantID,
			Kind:     string(key.Kind),
			Name:     key.Name,
			Target:   key.ManagedBy,
		}
		jobData, err := json.Marshal(data)
		require.NoError(t, err)

		err = handler.OnJobFailed(t.Context(), orbital.Job{
			ID:           jobID,
			Data:         jobData,
			Type:         announcekey.JobType,
			ErrorMessage: "agent failed",
		})
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingFailed, got.KeyProcessingState.Status)
		assert.Equal(t, jobID.String(), got.KeyProcessingState.JobID)
		assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState, "lifecycle state must not be mutated")
	})

	t.Run("should error on invalid job data", func(t *testing.T) {
		db := newTestDB(t)
		keyStore := storesql.NewKeyStore(db)

		handler := announcekey.NewJobHandler(keyStore, passingValidator())
		err := handler.OnJobFailed(t.Context(), orbital.Job{
			ID:   guuid.UUID(uuid.NewV7()),
			Data: []byte("not-json"),
			Type: announcekey.JobType,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal job data")
	})

	t.Run("should propagate store error", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		realStore := storesql.NewKeyStore(db)
		injected := errors.New("db error")

		handler := announcekey.NewJobHandler(&stubProcessingStateUpdater{Key: realStore, err: injected}, passingValidator())

		data := announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID, Kind: string(key.Kind), Name: key.Name, Target: key.ManagedBy}
		jobData, err := json.Marshal(data)
		require.NoError(t, err)

		err = handler.OnJobFailed(t.Context(), orbital.Job{ID: guuid.UUID(uuid.NewV7()), Data: jobData, Type: announcekey.JobType})
		assert.ErrorIs(t, err, injected)
	})
}

func TestJobHandler_OnJobCanceled(t *testing.T) {
	db := newTestDB(t)
	key := seedTenantAndKey(t, db)
	keyStore := storesql.NewKeyStore(db)

	handler := announcekey.NewJobHandler(keyStore, passingValidator())
	jobID := guuid.UUID(uuid.NewV7())

	data := announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID, Kind: string(key.Kind), Name: key.Name, Target: key.ManagedBy}
	jobData, err := json.Marshal(data)
	require.NoError(t, err)

	err = handler.OnJobCanceled(t.Context(), orbital.Job{ID: jobID, Data: jobData, Type: announcekey.JobType})
	require.NoError(t, err)

	got, err := keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	// OnJobCanceled is intentionally a no-op: stale-cancel must not clobber a
	// key that the caller has already moved on with via a newer job.
	// Validation-cancel marks the key Failed inside ConfirmJob itself.
	assert.Equal(t, key.KeyProcessingState.Status, got.KeyProcessingState.Status)
	assert.Equal(t, key.KeyProcessingState.JobID, got.KeyProcessingState.JobID)
}

func TestJobHandler_OnJobDone(t *testing.T) {
	t.Run("should mark processing state completed", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)

		handler := announcekey.NewJobHandler(keyStore, passingValidator())
		jobID := guuid.UUID(uuid.NewV7())

		data := announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID, Kind: string(key.Kind), Name: key.Name, Target: key.ManagedBy}
		jobData, err := json.Marshal(data)
		require.NoError(t, err)

		err = handler.OnJobDone(t.Context(), orbital.Job{ID: jobID, Data: jobData, Type: announcekey.JobType})
		require.NoError(t, err)

		got, err := keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
		assert.Equal(t, jobID.String(), got.KeyProcessingState.JobID)
		assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState, "lifecycle state must not be mutated")
	})

	t.Run("should error on invalid job data", func(t *testing.T) {
		db := newTestDB(t)
		keyStore := storesql.NewKeyStore(db)

		handler := announcekey.NewJobHandler(keyStore, passingValidator())
		err := handler.OnJobDone(t.Context(), orbital.Job{
			ID:   guuid.UUID(uuid.NewV7()),
			Data: []byte("not-json"),
			Type: announcekey.JobType,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unmarshal job data")
	})

	t.Run("should propagate store error", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		realStore := storesql.NewKeyStore(db)
		injected := errors.New("db error")

		handler := announcekey.NewJobHandler(&stubProcessingStateUpdater{Key: realStore, err: injected}, passingValidator())

		data := announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID, Kind: string(key.Kind), Name: key.Name, Target: key.ManagedBy}
		jobData, err := json.Marshal(data)
		require.NoError(t, err)

		err = handler.OnJobDone(t.Context(), orbital.Job{ID: guuid.UUID(uuid.NewV7()), Data: jobData, Type: announcekey.JobType})
		assert.ErrorIs(t, err, injected)
	})
}

func TestJobHandler_ConfirmJob(t *testing.T) {
	completeType := orbital.CompleteJobConfirmer().Type()
	cancelType := orbital.CancelJobConfirmer("").Type()
	continueType := orbital.ContinueJobConfirmer().Type()

	taskDataFor := func(key model.Key) []byte {
		raw, err := json.Marshal(announcekey.TaskData{
			KeyID:    key.ID,
			TenantID: key.TenantID,
			Kind:     string(key.Kind),
			Name:     key.Name,
			Target:   key.ManagedBy,
		})
		require.NoError(t, err)
		return raw
	}

	t.Run("completes and transitions Pending->InProgress when valid", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)
		jobID := guuid.UUID(uuid.NewV7())

		require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingPending,
			NewJobID:  jobID.String(),
		}))

		handler := announcekey.NewJobHandler(keyStore, passingValidator())

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: jobID, Data: taskDataFor(key)})
		require.NoError(t, err)
		assert.Equal(t, completeType, res.Type())

		got, err := keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingInProgress, got.KeyProcessingState.Status)
		assert.Equal(t, jobID.String(), got.KeyProcessingState.JobID)
	})

	t.Run("continues when key is missing — may not be committed yet", func(t *testing.T) {
		db := newTestDB(t)
		keyStore := storesql.NewKeyStore(db)
		handler := announcekey.NewJobHandler(keyStore, passingValidator())

		jobData, _ := json.Marshal(announcekey.TaskData{KeyID: uuid.New().String(), TenantID: uuid.New().String()})

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: guuid.UUID(uuid.NewV7()), Data: jobData})
		require.NoError(t, err)
		assert.Equal(t, continueType, res.Type())
	})

	t.Run("cancels when key lifecycle is not pre-activation", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)
		jobID := guuid.UUID(uuid.NewV7())

		require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingPending,
			NewJobID:  jobID.String(),
		}))
		require.NoError(t, keyStore.UpdateKeyLifeCycleState(t.Context(), store.UpdateKeyLifeCycleStateQuery{
			ID:       key.ID,
			TenantID: key.TenantID,
			NewState: model.KeyLifeCycleActive,
		}))

		handler := announcekey.NewJobHandler(keyStore, passingValidator())

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: jobID, Data: taskDataFor(key)})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())

		// lifecycle-mismatch cancel must not clobber the key state.
		got, err := keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingPending, got.KeyProcessingState.Status)
	})

	t.Run("stale cancel: JobID mismatch leaves key untouched", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)

		linkedJobID := guuid.UUID(uuid.NewV7())
		require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingPending,
			NewJobID:  linkedJobID.String(),
		}))

		handler := announcekey.NewJobHandler(keyStore, passingValidator())

		// Different job ID than the one linked on the key.
		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: guuid.UUID(uuid.NewV7()), Data: taskDataFor(key)})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())

		got, err := keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingPending, got.KeyProcessingState.Status)
		assert.Equal(t, linkedJobID.String(), got.KeyProcessingState.JobID)
	})

	t.Run("validation-fail cancel marks key Failed", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)
		jobID := guuid.UUID(uuid.NewV7())

		require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingPending,
			NewJobID:  jobID.String(),
		}))

		failingV := &stubValidator{err: validator.NewValidationError(validator.FailedCondition, errors.New("parent gone"))}
		handler := announcekey.NewJobHandler(keyStore, failingV)

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: jobID, Data: taskDataFor(key)})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())

		got, err := keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyProcessingFailed, got.KeyProcessingState.Status)
		assert.Equal(t, jobID.String(), got.KeyProcessingState.JobID)
	})

	t.Run("cancels on invalid job data", func(t *testing.T) {
		db := newTestDB(t)
		keyStore := storesql.NewKeyStore(db)
		handler := announcekey.NewJobHandler(keyStore, passingValidator())

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{Data: []byte("not-json")})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())
	})
}

func TestJobHandler_JobType(t *testing.T) {
	h := announcekey.NewJobHandler(nil, nil)
	assert.Equal(t, announcekey.JobType, h.JobType())
}
