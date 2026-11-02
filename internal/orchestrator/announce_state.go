package orchestrator

import (
	"github.com/openkcm/krypton/pkg/model"
)

type announceState struct {
	state  model.KeyProcessingStatus
	errMsg string
}

func newAnnounceState() *announceState {
	return &announceState{}
}

func (r *announceState) withState(state model.KeyProcessingStatus) *announceState {
	r.state = state
	return r
}

func (r *announceState) withErrorMessage(msg string) *announceState {
	r.errMsg = msg
	return r
}

func (r *announceState) isTerminalState() bool {
	if r == nil {
		return false
	}
	return r.state != "" || r.errMsg != ""
}
