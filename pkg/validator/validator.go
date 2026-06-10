package validator

import (
	"context"

	"google.golang.org/grpc/codes"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

type KeyValidator interface {
	ValidateAnnounceKey(context.Context, AnnounceInput) *ValidationError
}

type ErrorKind int

const (
	Invalid ErrorKind = iota
	FailedCondition
	Internal
)

type ValidationError struct {
	code ErrorKind
	err  error
}

// NewValidationError constructs a ValidationError. Useful for tests that
// fake KeyValidator implementations.
func NewValidationError(kind ErrorKind, err error) *ValidationError {
	return &ValidationError{code: kind, err: err}
}

func (ve *ValidationError) ToProtoErrCode() codes.Code {
	switch ve.code {
	case Invalid:
		return codes.InvalidArgument
	case FailedCondition:
		return codes.FailedPrecondition
	}

	return codes.Internal
}

// ToProtoDetailCode maps the validation error to the proto.Code used in
// ErrorDetails: client-fixable errors abort, transient/internal errors retry.
func (ve *ValidationError) ToProtoDetailCode() proto.Code {
	if ve.code == Internal {
		return proto.Code_ERROR_CODE_RETRY
	}
	return proto.Code_ERROR_CODE_ABORT
}

func (ve *ValidationError) Error() string {
	if ve == nil {
		return ""
	}

	return ve.err.Error()
}
