package keys

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

// mapToProtoErr maps validator and keyoperator class sentinels to gRPC
// status + proto detail codes. Returns nil for unrecognized errors.
func mapToProtoErr(err error) error {
	switch {
	case err == nil:
		return nil

	case errors.Is(err, store.ErrTenantNotFound):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, validator.ErrInvalidTenantID.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, store.ErrKeyNotFound):
		return proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "key not found"),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, validator.ErrKeyTransientState):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, validator.ErrKeyTransientState.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, validator.ErrParentKeyTransientState):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, validator.ErrParentKeyTransientState.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, keylifecycle.ErrInvalidKeyStateTransition):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)

	case errors.Is(err, keyoperator.ErrKeyTransitionRejected):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, keyoperator.ErrKeyTransitionRejected.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, keyoperator.ErrKeyVersionTransitionRejected):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, keyoperator.ErrKeyVersionTransitionRejected.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, keyoperator.ErrParentNoUsableVersion):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, keyoperator.ErrParentNoUsableVersion.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)

	case errors.Is(err, keyoperator.ErrGenerateAndSealKeyMaterial):
		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, keyoperator.ErrGenerateAndSealKeyMaterial.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)

	case errors.Is(err, keyoperator.ErrUpdateKeyState),
		errors.Is(err, keyoperator.ErrCreateKeyVersion),
		errors.Is(err, keyoperator.ErrUpdateKeyVersionState),
		errors.Is(err, keyoperator.ErrGetKey),
		errors.Is(err, keyoperator.ErrGetParentKeyVersion):
		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, err.Error()),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return nil
}
