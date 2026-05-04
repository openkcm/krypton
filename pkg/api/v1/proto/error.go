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
