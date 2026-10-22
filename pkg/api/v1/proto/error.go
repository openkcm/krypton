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

func Retryable(err error) bool {
	if err == nil {
		return false
	}

	st, ok := status.FromError(err)
	if !ok {
		// Non-gRPC error (e.g., context canceled)
		return true
	}

	for _, detail := range st.Details() {
		if d, ok := detail.(*ErrorDetails); ok {
			return d.GetCode() == Code_ERROR_CODE_RETRY
		}
	}

	// No ErrorDetails = error did not originate from server, assume retryable
	return true
}
