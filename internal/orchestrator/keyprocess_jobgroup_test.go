package orchestrator_test

import (
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/orchestrator"
)

func TestJobGroupHandler_JobGroupType(t *testing.T) {
	h := orchestrator.NewKeyProcessJobGroupHandler(orchestrator.ActivateHandlerConfig())
	assert.Equal(t, orchestrator.ActivateKey, h.JobGroupType())
}

func TestJobGroupHandler_OnJobGroupDone(t *testing.T) {
	h := orchestrator.NewKeyProcessJobGroupHandler(orchestrator.ActivateHandlerConfig())
	assert.NoError(t, h.OnJobGroupDone(t.Context(), orbital.JobGroup{ID: uuid.New()}))
}

func TestJobGroupHandler_OnJobGroupFailed(t *testing.T) {
	h := orchestrator.NewKeyProcessJobGroupHandler(orchestrator.ActivateHandlerConfig())
	assert.NoError(t, h.OnJobGroupFailed(t.Context(), orbital.JobGroup{ID: uuid.New(), ErrorMessage: "boom"}))
}

func TestJobGroupHandler_OnJobGroupCanceled(t *testing.T) {
	h := orchestrator.NewKeyProcessJobGroupHandler(orchestrator.ActivateHandlerConfig())
	assert.NoError(t, h.OnJobGroupCanceled(t.Context(), orbital.JobGroup{ID: uuid.New()}))
}
