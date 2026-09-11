package sealer_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
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

func newSealerClient(t *testing.T, mgr cryptor.Sealer) sealer.ServiceClient {
	t.Helper()

	return newSealerClientInternal(t, mgr)
}

func newSealerClientWithRPCHandler(t *testing.T, mgr cryptor.Sealer) sealer.ServiceClient {
	t.Helper()

	return newSealerClientInternal(t, mgr, grpc.StatsHandler(securemem.NewRPCHandler()))
}

func newSealerClientInternal(t *testing.T, mgr cryptor.Sealer, opts ...grpc.ServerOption) sealer.ServiceClient {
	t.Helper()

	srv := grpc.NewServer(opts...)
	sealerSrv := sealer.NewSealerService(mgr)

	sealer.RegisterServiceServer(srv, sealerSrv)

	const bufSize = 1024 * 1024
	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.Serve(lis); err != nil {
			// Serve returns error on graceful stop; ignore it.
			assert.Fail(t, "sealer service server error", err)
		}
	}()
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}

	t.Cleanup(func() {
		srv.GracefulStop()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		conn.Close()
	})

	client := sealer.NewServiceClient(conn)
	return client
}
