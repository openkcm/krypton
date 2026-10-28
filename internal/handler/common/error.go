package common

import (
	"fmt"
	"time"

	"github.com/openkcm/orbital"
)

type orbitalStatus string

// RetryBackoff is the default duration the task scheduler waits
// before re-delivering a task after a transient failure.
const RetryBackoff = 30 * time.Second

const (
	orbitalStatusContinue orbitalStatus = "continue"
	orbitalStatusFail     orbitalStatus = "fail"
	orbitalStatusComplete orbitalStatus = "complete"
)

// OrbitalOperatorError carries an orbital task disposition (continue, fail,
// or complete) alongside an optional wrapped cause. It implements [error]
// so it can propagate through [store.ChainTransaction] error chains and be
// recovered with [errors.As] in task handlers.
type OrbitalOperatorError struct {
	status       orbitalStatus
	retryBackoff time.Duration
	err          error
}

var _ error = (*OrbitalOperatorError)(nil)

// OrbitalContinue returns an [OrbitalOperatorError] that signals the task
// should be retried after [RetryBackoff].
func OrbitalContinue(err error) *OrbitalOperatorError {
	return &OrbitalOperatorError{
		status:       orbitalStatusContinue,
		err:          err,
		retryBackoff: RetryBackoff,
	}
}

// OrbitalFail returns an [OrbitalOperatorError] that signals the task
// has permanently failed.
func OrbitalFail(err error) *OrbitalOperatorError {
	return &OrbitalOperatorError{
		status: orbitalStatusFail,
		err:    err,
	}
}

// OrbitalComplete returns an [OrbitalOperatorError] that signals the task
// completed successfully and no further processing is needed.
func OrbitalComplete() *OrbitalOperatorError {
	return &OrbitalOperatorError{
		status: orbitalStatusComplete,
	}
}

// Apply writes the task disposition to resp. It returns the underlying error
// only for the Continue status (to propagate through transaction chains).
// For Fail and Complete, the error is consumed and nil is returned.
func (r *OrbitalOperatorError) Apply(resp *orbital.HandlerResponse) error {
	switch r.status {
	case orbitalStatusContinue:
		resp.ContinueAndWaitFor(r.retryBackoff)
		return r.err
	case orbitalStatusFail:
		errMsg := ""
		if r.err != nil {
			errMsg = r.err.Error()
		}
		resp.Fail(errMsg)
		return nil
	case orbitalStatusComplete:
		resp.Complete()
		return nil
	default:
		resp.ContinueAndWaitFor(RetryBackoff)
		return fmt.Errorf("orbital: unknown status %q", r.status)
	}
}

// Error implements [error].
func (r *OrbitalOperatorError) Error() string {
	return fmt.Sprintf("orbital response: status=%v, err=%v", r.status, r.err)
}
