package announcekey_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"uuid"

	"github.com/lib/pq"
	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// taskCreateOverride lets unhappy-path tests inject a CreateKey error
// without standing up the full SQL machinery.
type taskCreateOverride struct {
	store.Key

	createErr error
}

func (t *taskCreateOverride) CreateKey(_ context.Context, _ model.Key) error {
	return t.createErr
}

func executeTask(t *testing.T, h orbital.HandlerFunc, data []byte) orbital.TaskResponse {
	t.Helper()
	return orbital.ExecuteHandler(t.Context(), h, orbital.TaskRequest{
		TaskID: uuid.NewV7(),
		Type:   announcekey.TaskType,
		Data:   data,
	})
}

func TestTaskHandler_HappyPath(t *testing.T) {
	db := newTestDB(t)
	key := seedTenantAndKey(t, db)
	keyStore := storesql.NewKeyStore(db)
	handler := announcekey.NewTaskHandler(keyStore)

	// Use a fresh key id (the tenant is reused).
	data := announcekey.TaskData{
		KeyID:    uuid.New().String(),
		TenantID: key.TenantID,
		Kind:     "K0",
		Name:     "freshly-announced",
		Target:   "agent",
	}
	payload, err := json.Marshal(data)
	require.NoError(t, err)

	resp := executeTask(t, handler, payload)
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status, "expected DONE, got %q (%s)", resp.Status, resp.ErrorMessage)
	assert.Empty(t, resp.ErrorMessage)

	got, err := keyStore.GetKeyByID(t.Context(), data.KeyID, data.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState)
}

func TestTaskHandler_CorruptPayload_TerminalFail(t *testing.T) {
	handler := announcekey.NewTaskHandler(&taskCreateOverride{})

	resp := executeTask(t, handler, []byte("not-json"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "unmarshal task data")
}

func TestTaskHandler_AlreadyExists_Idempotent(t *testing.T) {
	handler := announcekey.NewTaskHandler(&taskCreateOverride{createErr: store.ErrKeyAlreadyExists})

	data := announcekey.TaskData{
		KeyID:    uuid.New().String(),
		TenantID: uuid.New().String(),
		Kind:     "K0",
		Name:     "dupe",
		Target:   "agent",
	}
	payload, err := json.Marshal(data)
	require.NoError(t, err)

	resp := executeTask(t, handler, payload)
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)
}

func TestTaskHandler_ForeignKeyViolation_TerminalFail(t *testing.T) {
	fkErr := &pq.Error{Code: "23503", Message: "tenant fk violation"}
	handler := announcekey.NewTaskHandler(&taskCreateOverride{createErr: fkErr})

	data := announcekey.TaskData{
		KeyID:    uuid.New().String(),
		TenantID: uuid.New().String(),
		Kind:     "K0",
		Name:     "fk",
		Target:   "agent",
	}
	payload, err := json.Marshal(data)
	require.NoError(t, err)

	resp := executeTask(t, handler, payload)
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "foreign key")
}

func TestTaskHandler_TransientError_RetriesWithBackoff(t *testing.T) {
	handler := announcekey.NewTaskHandler(&taskCreateOverride{createErr: errors.New("network blip")})

	data := announcekey.TaskData{
		KeyID:    uuid.New().String(),
		TenantID: uuid.New().String(),
		Kind:     "K0",
		Name:     "transient",
		Target:   "agent",
	}
	payload, err := json.Marshal(data)
	require.NoError(t, err)

	resp := executeTask(t, handler, payload)
	assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status, "transient errors must not be terminal")
	assert.Positive(t, resp.ReconcileAfterSec, "expected non-zero backoff before retry")
}
