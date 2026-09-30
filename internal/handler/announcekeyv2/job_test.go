package announcekeyv2_test

import (
	"errors"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler/announcekeyv2"
	"github.com/openkcm/krypton/pkg/model"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestJobHandler_ConfirmJob_KeyExists_Completes(t *testing.T) {
	rootDB := newRootDB(t)
	key := seedRootTenantAndKey(t, rootDB, "agent")

	handler := announcekeyv2.NewJobHandler(storesql.NewTransactor(rootDB))

	res, err := handler.ConfirmJob(t.Context(), orbital.Job{
		ID:   uuid.NewV7(),
		Data: taskPayload(t, key),
	})
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteJobConfirmer().Type(), res.Type())
}

func TestJobHandler_ConfirmJob_KeyMissing_Cancels(t *testing.T) {
	rootDB := newRootDB(t)

	handler := announcekeyv2.NewJobHandler(storesql.NewTransactor(rootDB))

	ghost := model.NewKey(uuid.New().String(), "ghost", "K0", nil, "agent", nil)
	ghost.ID = uuid.New().String()

	res, err := handler.ConfirmJob(t.Context(), orbital.Job{
		ID:   uuid.NewV7(),
		Data: taskPayload(t, ghost),
	})
	require.NoError(t, err)
	assert.Equal(t, orbital.CancelJobConfirmer("").Type(), res.Type())
}

func TestJobHandler_ConfirmJob_StoreError_Continues(t *testing.T) {
	failing := &failingTransactor{err: errors.New("db down")}

	handler := announcekeyv2.NewJobHandler(failing)

	key := model.NewKey(uuid.New().String(), "any", "K0", nil, "agent", nil)
	key.ID = uuid.New().String()

	res, err := handler.ConfirmJob(t.Context(), orbital.Job{
		ID:   uuid.NewV7(),
		Data: taskPayload(t, key),
	})
	require.NoError(t, err)
	assert.Equal(t, orbital.ContinueJobConfirmer().Type(), res.Type())
}

func TestJobHandler_ConfirmJob_InvalidPayload_Cancels(t *testing.T) {
	rootDB := newRootDB(t)
	handler := announcekeyv2.NewJobHandler(storesql.NewTransactor(rootDB))

	res, err := handler.ConfirmJob(t.Context(), orbital.Job{
		ID:   uuid.NewV7(),
		Data: []byte("not-json"),
	})
	require.NoError(t, err)
	assert.Equal(t, orbital.CancelJobConfirmer("").Type(), res.Type())
}

func TestJobHandler_ResolveTasks(t *testing.T) {
	rootDB := newRootDB(t)
	handler := announcekeyv2.NewJobHandler(storesql.NewTransactor(rootDB))

	res, err := handler.ResolveTasks(t.Context(), orbital.Job{
		ID:   uuid.NewV7(),
		Data: []byte(`{"id":"x"}`),
	}, orbital.TaskResolverCursor(""))
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteTaskResolver().Type(), res.Type())
}

func TestJobHandler_OnJobDone_NoOp(t *testing.T) {
	handler := announcekeyv2.NewJobHandler(nil)
	assert.NoError(t, handler.OnJobDone(t.Context(), orbital.Job{ID: uuid.NewV7()}))
}

func TestJobHandler_OnJobFailed_NoOp(t *testing.T) {
	handler := announcekeyv2.NewJobHandler(nil)
	assert.NoError(t, handler.OnJobFailed(t.Context(), orbital.Job{ID: uuid.NewV7(), ErrorMessage: "boom"}))
}

func TestJobHandler_OnJobCanceled_NoOp(t *testing.T) {
	handler := announcekeyv2.NewJobHandler(nil)
	assert.NoError(t, handler.OnJobCanceled(t.Context(), orbital.Job{ID: uuid.NewV7()}))
}

func TestJobHandler_JobType(t *testing.T) {
	handler := announcekeyv2.NewJobHandler(nil)
	assert.Equal(t, announcekeyv2.JobType, handler.JobType())
}
