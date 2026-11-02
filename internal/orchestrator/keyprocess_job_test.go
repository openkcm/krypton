package orchestrator_test

import (
	"encoding/json/v2"
	"testing"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/orchestrator"
)

func TestJobHandler_JobType(t *testing.T) {
	// given  when
	handler := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())

	// when
	assert.Equal(t, orchestrator.ActivateKey, handler.JobType())
}

func TestJobHandler_New(t *testing.T) {
	// given  when
	handler := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())

	// when
	assert.NotNil(t, handler)
}

func TestJobHandler_ConfirmJob(t *testing.T) {
	// given
	subj := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())

	// when
	res, err := subj.ConfirmJob(t.Context(), orbital.Job{})

	// then
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteJobConfirmer(), res)
}

func TestJobHandler_ResolveTasks(t *testing.T) {
	t.Run("invalid JSON input", func(t *testing.T) {
		// given
		subj := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())

		// when
		res, err := subj.ResolveTasks(t.Context(), orbital.Job{
			Data: []byte("invalid-json"),
			Type: orchestrator.ActivateKey,
		}, orbital.TaskResolverCursor(""))

		// then
		require.NoError(t, err)
		assert.Equal(t, orbital.CancelTaskResolver("").Type(), res.Type())
	})

	t.Run("empty identifiers list", func(t *testing.T) {
		// given
		subj := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())
		keyLayer := orchestrator.KeyLayer{
			Identifiers: []orchestrator.KeyIdentifier{},
		}
		jobData, err := json.Marshal(keyLayer)
		require.NoError(t, err)

		// when
		res, err := subj.ResolveTasks(t.Context(), orbital.Job{
			Data: jobData,
			Type: orchestrator.ActivateKey,
		}, orbital.TaskResolverCursor(""))

		// then
		require.NoError(t, err)
		assert.Equal(t, orbital.CancelTaskResolver("").Type(), res.Type())
	})

	t.Run("resolves task per key identifier", func(t *testing.T) {
		// given
		subj := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())
		keyLayer := orchestrator.KeyLayer{
			Identifiers: []orchestrator.KeyIdentifier{
				{
					ID:       "id1",
					TenantID: "tenant",
				},
				{
					ID:       "id2",
					TenantID: "tenant",
				},
			},
		}
		jobData, err := json.Marshal(keyLayer)
		require.NoError(t, err)

		expTaskInfos := make([]orbital.TaskInfo, 0, len(keyLayer.Identifiers))
		for _, id := range keyLayer.Identifiers {
			jobData, err := json.Marshal(id)
			require.NoError(t, err)

			expTaskInfos = append(expTaskInfos, orbital.TaskInfo{
				Data:   jobData,
				Type:   orchestrator.ActivateKey,
				Target: orchestrator.DefaultLocalTargetName,
			})
		}
		expRes := orbital.CompleteTaskResolver().WithTaskInfo(expTaskInfos)

		// when
		res, err := subj.ResolveTasks(t.Context(), orbital.Job{
			Data: jobData,
			Type: orchestrator.ActivateKey,
		}, orbital.TaskResolverCursor(""))

		// then
		require.NoError(t, err)
		assert.Equal(t, expRes, res)
	})
}

func TestJobHandler_OnJobCanceled(t *testing.T) {
	// given
	subj := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())

	// when
	err := subj.OnJobCanceled(t.Context(), orbital.Job{})

	// then
	assert.NoError(t, err)
}

func TestJobHandler_OnJobDone(t *testing.T) {
	// given
	subj := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())

	// when
	err := subj.OnJobDone(t.Context(), orbital.Job{})

	// then
	assert.NoError(t, err)
}

func TestJobHandler_OnJobFailed(t *testing.T) {
	// given
	subj := orchestrator.NewKeyProcessJobHandler(orchestrator.ActivateHandlerConfig())

	// when
	err := subj.OnJobFailed(t.Context(), orbital.Job{})

	// then
	assert.NoError(t, err)
}
