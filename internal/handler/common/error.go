package common

import (
	"fmt"
	"time"

	"github.com/openkcm/orbital"
)

type orbitalStatus int

const retryBackoff = 30 * time.Second

const (
	orbitalStatusContinue orbitalStatus = iota
	orbitalStatusFail
	orbitalStatusComplete
)

type OrbitalOperatorError struct {
	status       orbitalStatus
	retryBackoff time.Duration
	err          error
}

func OrbitalContinue(err error) *OrbitalOperatorError {
	return &OrbitalOperatorError{
		status:       orbitalStatusContinue,
		err:          err,
		retryBackoff: retryBackoff,
	}
}

func OrbitalFail(err error) *OrbitalOperatorError {
	return &OrbitalOperatorError{
		status: orbitalStatusFail,
		err:    err,
	}
}

func OrbitalComplete() *OrbitalOperatorError {
	return &OrbitalOperatorError{
		status: orbitalStatusComplete,
	}
}

func (r *OrbitalOperatorError) Apply(resp *orbital.HandlerResponse) error {
	switch r.status {
	case orbitalStatusContinue:
		resp.ContinueAndWaitFor(r.retryBackoff)
		return r.err
	case orbitalStatusFail:
		resp.Fail(r.err.Error())
		return nil
	default:
		resp.Complete()
		return nil
	}
}

var _ error = (*OrbitalOperatorError)(nil)

// Error implements [error].
func (r *OrbitalOperatorError) Error() string {
	return fmt.Sprintf("orbital response: status=%v, err=%v", r.status, r.err)
}
