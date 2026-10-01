package announcekey_test

import (
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/handler/announcekey"
)

func TestJobGroupHandler_JobGroupType(t *testing.T) {
	h := announcekey.NewJobGroupHandler()
	assert.Equal(t, announcekey.JobGroupType, h.JobGroupType())
}

func TestJobGroupHandler_OnJobGroupDone(t *testing.T) {
	h := announcekey.NewJobGroupHandler()
	assert.NoError(t, h.OnJobGroupDone(t.Context(), orbital.JobGroup{ID: uuid.NewV7()}))
}

func TestJobGroupHandler_OnJobGroupFailed(t *testing.T) {
	h := announcekey.NewJobGroupHandler()
	assert.NoError(t, h.OnJobGroupFailed(t.Context(), orbital.JobGroup{ID: uuid.NewV7(), ErrorMessage: "boom"}))
}

func TestJobGroupHandler_OnJobGroupCanceled(t *testing.T) {
	h := announcekey.NewJobGroupHandler()
	assert.NoError(t, h.OnJobGroupCanceled(t.Context(), orbital.JobGroup{ID: uuid.NewV7()}))
}
