package announcekeyv2_test

import (
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/handler/announcekeyv2"
)

func TestJobGroupHandler_JobGroupType(t *testing.T) {
	h := announcekeyv2.NewJobGroupHandler()
	assert.Equal(t, announcekeyv2.JobGroupType, h.JobGroupType())
}

func TestJobGroupHandler_OnJobGroupDone(t *testing.T) {
	h := announcekeyv2.NewJobGroupHandler()
	assert.NoError(t, h.OnJobGroupDone(t.Context(), orbital.JobGroup{ID: uuid.NewV7()}))
}

func TestJobGroupHandler_OnJobGroupFailed(t *testing.T) {
	h := announcekeyv2.NewJobGroupHandler()
	assert.NoError(t, h.OnJobGroupFailed(t.Context(), orbital.JobGroup{ID: uuid.NewV7(), ErrorMessage: "boom"}))
}

func TestJobGroupHandler_OnJobGroupCanceled(t *testing.T) {
	h := announcekeyv2.NewJobGroupHandler()
	assert.NoError(t, h.OnJobGroupCanceled(t.Context(), orbital.JobGroup{ID: uuid.NewV7()}))
}
