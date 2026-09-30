package proto

import (
	"log/slog"

	"google.golang.org/grpc/status"
)

func ErrDetailsWithCode(st *status.Status, c Code) error {
	ds, err := st.WithDetails(&ErrorDetails{
		Code: c,
	})
	if err != nil {
		slog.Error("failed to create error details")
		return st.Err()
	}
	return ds.Err()
}

// CodeFromError extracts the Krypton [Code] carried in a gRPC error's status
// details, as attached by [ErrDetailsWithCode]. It returns
// Code_ERROR_CODE_UNSPECIFIED when err is nil, is not a gRPC status error, or
// carries no ErrorDetails. Callers use it to classify a remote failure as
// terminal (ABORT) versus retryable (RETRY/unspecified).
func CodeFromError(err error) Code {
	if err == nil {
		return Code_ERROR_CODE_UNSPECIFIED
	}
	st, ok := status.FromError(err)
	if !ok {
		return Code_ERROR_CODE_UNSPECIFIED
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*ErrorDetails); ok {
			return ed.GetCode()
		}
	}
	return Code_ERROR_CODE_UNSPECIFIED
}
