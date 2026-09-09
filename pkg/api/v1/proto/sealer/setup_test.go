package sealer_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

type mockManager struct {
	FnSeal   func(context.Context, cryptor.SealRequest) (cryptor.SealResponse, error)
	FnUnseal func(context.Context, cryptor.UnsealRequest) (cryptor.UnsealResponse, error)
}

var _ cryptor.Sealer = &mockManager{}

// Seal implements [cryptor.Sealer].
func (m *mockManager) Seal(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
	return m.FnSeal(ctx, req)
}

// Unseal implements [cryptor.Sealer].
func (m *mockManager) Unseal(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
	return m.FnUnseal(ctx, req)
}

func newMockManager(t *testing.T) *mockManager {
	t.Helper()
	return &mockManager{
		FnSeal: func(context.Context, cryptor.SealRequest) (cryptor.SealResponse, error) {
			assert.Fail(t, "unexpected call to Seal")
			return cryptor.SealResponse{}, nil
		},
		FnUnseal: func(context.Context, cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			assert.Fail(t, "unexpected call to Unseal")
			return cryptor.UnsealResponse{}, nil
		},
	}
}

func assertErrorDetails(t *testing.T, expCode proto.Code, actErr error) {
	t.Helper()

	st := status.Convert(actErr)
	dts := st.Details()
	require.Len(t, dts, 1, "expected 1 error detail")

	dt, ok := dts[0].(*proto.ErrorDetails)
	require.True(t, ok, "expected error details of type proto.ErrorDetails")
	assert.Equal(t, expCode, dt.GetCode())
}
