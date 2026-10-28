package proto_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

func TestRetryable(t *testing.T) {
	// given
	tts := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "should return false for nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "should return true for non-gRPC error",
			err:      errors.New("some error"),
			expected: true,
		},
		{
			name:     "should return true for context canceled error",
			err:      context.Canceled,
			expected: true,
		},
		{
			name:     "should return true for gRPC error with RETRY code",
			err:      proto.ErrDetailsWithCode(status.New(codes.Internal, "retry me"), proto.Code_ERROR_CODE_RETRY),
			expected: true,
		},
		{
			name:     "should return false for gRPC error with ABORT code",
			err:      proto.ErrDetailsWithCode(status.New(codes.Internal, "abort"), proto.Code_ERROR_CODE_ABORT),
			expected: false,
		},
		{
			name:     "should return false for gRPC error with UNSPECIFIED code",
			err:      proto.ErrDetailsWithCode(status.New(codes.Internal, "unspecified"), proto.Code_ERROR_CODE_UNSPECIFIED),
			expected: false,
		},
		{
			name:     "should return true for gRPC error without ErrorDetails",
			err:      status.Error(codes.Internal, "no details"),
			expected: true,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			actual := proto.Retryable(tt.err)

			// then
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestErrDetailsWithCode(t *testing.T) {
	tts := []struct {
		name       string
		grpcCode   codes.Code
		message    string
		detailCode proto.Code
	}{
		{
			name:       "should attach RETRY code to Internal status",
			grpcCode:   codes.Internal,
			message:    "internal error",
			detailCode: proto.Code_ERROR_CODE_RETRY,
		},
		{
			name:       "should attach ABORT code to InvalidArgument status",
			grpcCode:   codes.InvalidArgument,
			message:    "invalid argument",
			detailCode: proto.Code_ERROR_CODE_ABORT,
		},
		{
			name:       "should attach UNSPECIFIED code to NotFound status",
			grpcCode:   codes.NotFound,
			message:    "not found",
			detailCode: proto.Code_ERROR_CODE_UNSPECIFIED,
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// given
			st := status.New(tt.grpcCode, tt.message)

			// when
			err := proto.ErrDetailsWithCode(st, tt.detailCode)

			// then
			require.Error(t, err)

			actStatus := status.Convert(err)
			assert.Equal(t, tt.grpcCode, actStatus.Code())
			assert.Equal(t, tt.message, actStatus.Message())

			details := actStatus.Details()
			require.Len(t, details, 1, "expected exactly 1 error detail")

			errDetail, ok := details[0].(*proto.ErrorDetails)
			require.True(t, ok, "expected error detail of type *proto.ErrorDetails")
			assert.Equal(t, tt.detailCode, errDetail.GetCode())
		})
	}
}
