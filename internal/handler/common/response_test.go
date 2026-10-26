package common_test

import (
	"testing"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/handler/common"
)

func TestOrbitalContinue(t *testing.T) {
	// given
	// when
	subj := common.OrbitalContinue(assert.AnError)

	// then
	resp := applyResponse(t, subj)
	assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
	assert.Positive(t, resp.ReconcileAfterSec)
}

func TestOrbitalFail(t *testing.T) {
	// given
	// when
	subj := common.OrbitalFail(assert.AnError)

	// then
	resp := applyResponse(t, subj)
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Zero(t, resp.ReconcileAfterSec)
}

func TestOrbitalComplete(t *testing.T) {
	// given
	// when
	subj := common.OrbitalComplete()

	// then
	resp := applyResponse(t, subj)
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)
	assert.Zero(t, resp.ReconcileAfterSec)
}

func TestApply(t *testing.T) {
	tts := []struct {
		name string
		subj *common.OrbitalResponseError
		exp  error
	}{
		{
			name: "continue",
			subj: common.OrbitalContinue(assert.AnError),
			exp:  assert.AnError,
		},
		{
			name: "failed",
			subj: common.OrbitalFail(assert.AnError),
			exp:  nil,
		},
		{
			name: "complete",
			subj: common.OrbitalComplete(),
			exp:  nil,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			actErr := tt.subj.Apply(&orbital.HandlerResponse{})

			// then
			assert.ErrorIs(t, actErr, tt.exp)
		})
	}
}
