package keys

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

func mapToProtoErr(err error) error {
	switch {
	case errors.Is(err, store.ErrTenantNotFound):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, validator.ErrInvalidTenantID.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, keyoperator.ErrKeyConflict):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, keyoperator.ErrKeyConflict.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return proto.ErrDetailsWithCode(
		status.New(codes.Internal, err.Error()),
		proto.Code_ERROR_CODE_RETRY,
	)
}
