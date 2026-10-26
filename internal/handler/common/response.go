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

type OrbitalResponseError struct {
	status       orbitalStatus
	retryBackoff time.Duration
	err          error
}

func OrbitalContinue(err error) *OrbitalResponseError {
	return &OrbitalResponseError{
		status:       orbitalStatusContinue,
		err:          err,
		retryBackoff: retryBackoff,
	}
}

func OrbitalFail(err error) *OrbitalResponseError {
	return &OrbitalResponseError{
		status: orbitalStatusFail,
		err:    err,
	}
}

func OrbitalComplete() *OrbitalResponseError {
	return &OrbitalResponseError{
		status: orbitalStatusComplete,
	}
}

func (r *OrbitalResponseError) Apply(resp *orbital.HandlerResponse) error {
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

var _ error = (*OrbitalResponseError)(nil)

// Error implements [error].
func (r *OrbitalResponseError) Error() string {
	return fmt.Sprintf("orbital response: status=%v, err=%v", r.status, r.err)
}
