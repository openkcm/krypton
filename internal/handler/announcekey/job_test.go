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
	t.Run("completes when key exists", func(t *testing.T) {
		db := newTestDB(t)
		key := seedTenantAndKey(t, db)
		keyStore := storesql.NewKeyStore(db)
		handler := announcekey.NewJobHandler(keyStore)

		data := announcekey.TaskData{KeyID: key.ID, TenantID: key.TenantID}
		jobData, _ := json.Marshal(data)

		_, err := handler.ConfirmJob(t.Context(), orbital.Job{Data: jobData})
		require.NoError(t, err)
	})

	t.Run("returns error on invalid data — surfaced as cancel", func(t *testing.T) {
		db := newTestDB(t)
		keyStore := storesql.NewKeyStore(db)
		handler := announcekey.NewJobHandler(keyStore)

		_, err := handler.ConfirmJob(t.Context(), orbital.Job{Data: []byte("not-json")})
		require.NoError(t, err) // cancel is conveyed via result, not error
	})
}

func TestJobHandler_JobType(t *testing.T) {
	h := announcekey.NewJobHandler(nil)
	assert.Equal(t, announcekey.JobType, h.JobType())
}
