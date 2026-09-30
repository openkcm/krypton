package announcekeyv2

import (
	"google.golang.org/grpc"

	"github.com/openkcm/krypton/pkg/model"
)

type sharedResult struct {
	procState model.KeyProcessingStatus
	failMsg   string
	conn      *grpc.ClientConn
	err       error
}

func newSharedResult() *sharedResult {
	return &sharedResult{}
}

func (r *sharedResult) withError(err error) *sharedResult {
	r.err = err
	return r
}

func (r *sharedResult) withProcState(procState model.KeyProcessingStatus) *sharedResult {
	r.procState = procState
	return r
}

func (r *sharedResult) withFailMsg(failMsg string) *sharedResult {
	r.failMsg = failMsg
	return r
}

func (r *sharedResult) withConn(conn *grpc.ClientConn) *sharedResult {
	r.conn = conn
	return r
}

func (r *sharedResult) isResulted() bool {
	if r == nil {
		return false
	}
	return r.procState != "" || r.failMsg != ""
}
