package announcekey_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestJobHandler_OnJobFailed(t *testing.T) {
	t.Run("should mark processing state failed", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)

		handler := announcekey.NewJobHandler(keyStore)
		jobID := uuid.Must(uuid.NewUUID())

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

		handler := announcekey.NewJobHandler(keyStore)
		err := handler.OnJobFailed(t.Context(), orbital.Job{
			ID:   uuid.Must(uuid.NewUUID()),
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

		handler := announcekey.NewJobHandler(&stubProcessingStateUpdater{Key: realStore, err: injected})

		data := announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID, Kind: string(key.Kind), Name: key.Name, Target: key.ManagedBy}
		jobData, err := json.Marshal(data)
		require.NoError(t, err)

		err = handler.OnJobFailed(t.Context(), orbital.Job{ID: uuid.Must(uuid.NewUUID()), Data: jobData, Type: announcekey.JobType})
		assert.ErrorIs(t, err, injected)
	})
}

func TestJobHandler_OnJobCanceled(t *testing.T) {
	db := newTestDB(t)
	key := seedTenantAndKey(t, db)
	keyStore := storesql.NewKeyStore(db)

	handler := announcekey.NewJobHandler(keyStore)
	jobID := uuid.Must(uuid.NewUUID())

	data := announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID, Kind: string(key.Kind), Name: key.Name, Target: key.ManagedBy}
	jobData, err := json.Marshal(data)
	require.NoError(t, err)

	err = handler.OnJobCanceled(t.Context(), orbital.Job{ID: jobID, Data: jobData, Type: announcekey.JobType})
	require.NoError(t, err)

	got, err := keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyProcessingFailed, got.KeyProcessingState.Status)
	assert.Equal(t, jobID.String(), got.KeyProcessingState.JobID)
}

func TestJobHandler_OnJobDone(t *testing.T) {
	db := newTestDB(t)
	key := seedTenantAndKey(t, db)
	keyStore := storesql.NewKeyStore(db)

	handler := announcekey.NewJobHandler(keyStore)
	jobID := uuid.Must(uuid.NewUUID())

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
}

func TestJobHandler_ConfirmJob(t *testing.T) {
	completeType := orbital.CompleteJobConfirmer().Type()
	cancelType := orbital.CancelJobConfirmer("").Type()
	continueType := orbital.ContinueJobConfirmer().Type()

	t.Run("completes when key is in pre-activation, in-progress, and linked to this job", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)
		jobID := uuid.Must(uuid.NewUUID())

		require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingInProgress,
			NewJobID:  jobID.String(),
		}))

		handler := announcekey.NewJobHandler(keyStore)
		jobData, _ := json.Marshal(announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID})

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: jobID, Data: jobData})
		require.NoError(t, err)
		assert.Equal(t, completeType, res.Type())
	})

	t.Run("continues when key is missing — may not be committed yet", func(t *testing.T) {
		db := newTestDB(t)
		keyStore := storesql.NewKeyStore(db)
		handler := announcekey.NewJobHandler(keyStore)

		jobData, _ := json.Marshal(announcekey.TaskData{KeyID: uuid.NewString(), TenantID: uuid.NewString()})

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: uuid.Must(uuid.NewUUID()), Data: jobData})
		require.NoError(t, err)
		assert.Equal(t, continueType, res.Type())
	})

	t.Run("cancels when key lifecycle is not pre-activation", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)
		jobID := uuid.Must(uuid.NewUUID())

		require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingInProgress,
			NewJobID:  jobID.String(),
		}))
		require.NoError(t, keyStore.UpdateKeyLifeCycleState(t.Context(), store.UpdateKeyLifeCycleStateQuery{
			ID:       key.ID,
			TenantID: key.TenantID,
			NewState: model.KeyLifeCycleActive,
		}))

		handler := announcekey.NewJobHandler(keyStore)
		jobData, _ := json.Marshal(announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID})

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: jobID, Data: jobData})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())
	})

	t.Run("cancels when key processing status is not in-progress", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)
		jobID := uuid.Must(uuid.NewUUID())

		require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingFailed,
			NewJobID:  jobID.String(),
		}))

		handler := announcekey.NewJobHandler(keyStore)
		jobData, _ := json.Marshal(announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID})

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: jobID, Data: jobData})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())
	})

	t.Run("cancels when JobID does not match", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)

		linkedJobID := uuid.Must(uuid.NewUUID())
		require.NoError(t, keyStore.UpdateKeyProcessingState(t.Context(), store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingInProgress,
			NewJobID:  linkedJobID.String(),
		}))

		handler := announcekey.NewJobHandler(keyStore)
		jobData, _ := json.Marshal(announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID})

		// Different job ID than the one linked on the key.
		res, err := handler.ConfirmJob(t.Context(), orbital.Job{ID: uuid.Must(uuid.NewUUID()), Data: jobData})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())
	})

	t.Run("cancels on invalid job data", func(t *testing.T) {
		db := newTestDB(t)
		keyStore := storesql.NewKeyStore(db)
		handler := announcekey.NewJobHandler(keyStore)

		res, err := handler.ConfirmJob(t.Context(), orbital.Job{Data: []byte("not-json")})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())
	})
}

func TestJobHandler_JobType(t *testing.T) {
	h := announcekey.NewJobHandler(nil)
	assert.Equal(t, announcekey.JobType, h.JobType())
}
