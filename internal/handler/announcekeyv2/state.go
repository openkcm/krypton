package announcekeyv2

import (
	"github.com/openkcm/krypton/pkg/model"
)

type sharedState struct {
	state  model.KeyProcessingStatus
	errMsg string
}

func newSharedState() *sharedState {
	return &sharedState{}
}

func (r *sharedState) withState(state model.KeyProcessingStatus) *sharedState {
	r.state = state
	return r
}

func (r *sharedState) withErrorMessage(msg string) *sharedState {
	r.errMsg = msg
	return r
}

func (r *sharedState) isTerminalState() bool {
	if r == nil {
		return false
	}
	return r.state != "" || r.errMsg != ""
}
