package sealer_test

import (
	"context"
	"net"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
)

func TestSealer(t *testing.T) {
	t.Run("should seal plaintext successfully", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		expTenantID := uuid.New().String()
		expKeyID := uuid.New().String()
		expKeyVersion := 1
		expPlaintext := []byte("test plaintext")
		expAad := []byte("test aad")
		expRespBytes := []byte("actual ciphertext")

		actReqPlaintext := make([]byte, len(expPlaintext))
		var actReq cryptor.SealRequest
		mgr.FnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			actReq = req
			copy(actReqPlaintext, req.Plaintext.SecureBytes())

			cData, err := securemem.NewData("resp", len(expRespBytes))
			require.NoError(t, err)

			t.Cleanup(func() {
				cData.Destroy()
			})

			copy(cData.SecureBytes(), expRespBytes)

			return cryptor.SealResponse{
				Ciphertext: cData,
			}, nil
		}

		cli := newSealerClient(t, mgr)

		// when
		actRes, err := cli.Seal(ctx, &sealer.SealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Plaintext:  expPlaintext,
			Aad:        expAad,
		})

		// then
		require.NoError(t, err)
		assert.Equal(t, expRespBytes, actRes.GetCiphertext())

		assert.Equal(t, expTenantID, actReq.TenantID)
		assert.Equal(t, expKeyID, actReq.KeyID)
		assert.Equal(t, expKeyVersion, actReq.KeyVersion)
		assert.Equal(t, expPlaintext, actReqPlaintext)
		assert.Equal(t, expAad, actReq.AAD)
	})

	t.Run("should track input and output in vault", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)
		expTenantID := uuid.New().String()
		expKeyID := uuid.New().String()
		expKeyVersion := 1
		expPlaintext := []byte("test plaintext")
		expAad := []byte("test aad")

		var actVault *securemem.MemVault
		mgr.FnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			vault, ok := sealer.VaultFromContext(ctx) // ensure vault is in context
			require.True(t, ok)
			actVault = vault

			expRespBytes := []byte("actual ciphertext")
			cData, err := securemem.NewData("resp", len(expRespBytes))
			require.NoError(t, err)

			t.Cleanup(func() {
				cData.Destroy()
			})

			copy(cData.SecureBytes(), expRespBytes)

			return cryptor.SealResponse{
				Ciphertext: cData,
			}, nil
		}

		cli := newSealerClient(t, mgr)

		// when
		actRes, err := cli.Seal(ctx, &sealer.SealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Plaintext:  expPlaintext,
			Aad:        expAad,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, actRes)

		// check context value
		_, ok := actVault.Get("input")
		assert.True(t, ok)
		_, ok = actVault.Get("output")
		assert.True(t, ok)

		err = actVault.DestroyAll()
		assert.NoError(t, err)
	})

	t.Run("should return internal error when sealing fails", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		expTenantID := uuid.New().String()
		expKeyID := uuid.New().String()
		expKeyVersion := 1
		expPlaintext := []byte("test plaintext")
		expAad := []byte("test aad")

		mgr.FnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			return cryptor.SealResponse{}, assert.AnError
		}

		cli := newSealerClient(t, mgr)

		// when
		actRes, err := cli.Seal(ctx, &sealer.SealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Plaintext:  expPlaintext,
			Aad:        expAad,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assert.Equal(t, "failed to seal the plaintext", status.Convert(err).Message())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)

		assert.Nil(t, actRes)
	})

	t.Run("should return internal error when vault import fails", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		expTenantID := uuid.New().String()
		expKeyID := uuid.New().String()
		expKeyVersion := 1
		expPlaintext := []byte("test plaintext")
		expAad := []byte("test aad")

		ciphertext, err := securemem.NewData("output", 10)
		require.NoError(t, err)

		t.Cleanup(func() {
			ciphertext.Destroy()
		})

		copy(ciphertext.SecureBytes(), []byte("ciphertext"))

		mgr.FnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			vault, ok := sealer.VaultFromContext(ctx) // ensure vault is in context
			require.True(t, ok)

			data, err := securemem.NewData("output", 10)
			require.NoError(t, err)
			t.Cleanup(func() {
				data.Destroy()
			})

			require.NoError(t, vault.Import("output", data)) // simulate import failure

			return cryptor.SealResponse{
				Ciphertext: ciphertext,
			}, nil
		}

		cli := newSealerClient(t, mgr)

		// when
		actRes, err := cli.Seal(ctx, &sealer.SealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Plaintext:  expPlaintext,
			Aad:        expAad,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assert.Equal(t, "failed to import the ciphertext into the vault", status.Convert(err).Message())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
		assert.Nil(t, ciphertext.SecureBytes()) // ensure ciphertext is destroyed on import failure

		assert.Nil(t, actRes)
	})
}

func newSealerClient(t *testing.T, mgr cryptor.Sealer) sealer.ServiceClient {
	t.Helper()

	srv := grpc.NewServer()
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

func TestVaultFromContext(t *testing.T) {
	vault := securemem.NewMemVault()

	tests := []struct {
		name   string
		ctx    func() context.Context
		expOk  bool
		expOut *securemem.MemVault
	}{
		{
			name: "should return vault when context has a vault set",
			ctx: func() context.Context {
				return sealer.VaultToContext(t.Context(), vault)
			},
			expOk:  true,
			expOut: vault,
		},
		{
			name: "should return nil and false when context has no vault",
			ctx: func() context.Context {
				return t.Context()
			},
			expOk:  false,
			expOut: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// given
			ctx := tc.ctx()

			// when
			vault, ok := sealer.VaultFromContext(ctx)

			// then
			assert.Equal(t, tc.expOut, vault)
			assert.Equal(t, tc.expOk, ok)
		})
	}
}

func TestVaultToContext(t *testing.T) {
	tests := []struct {
		name string
		ctx  func() context.Context
	}{
		{
			name: "should set vault in empty context",
			ctx: func() context.Context {
				return t.Context()
			},
		},
		{
			name: "should set vault in context that already has other values",
			ctx: func() context.Context {
				type otherKey struct{}
				return context.WithValue(t.Context(), otherKey{}, "other")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// given
			ctx := tc.ctx()
			vault := securemem.NewMemVault()

			// when
			enrichedCtx := sealer.VaultToContext(ctx, vault)

			// then
			actVault, ok := sealer.VaultFromContext(enrichedCtx)
			require.True(t, ok)
			assert.Equal(t, vault, actVault)

			// original context must not be modified
			origVault, origOk := sealer.VaultFromContext(ctx)
			assert.False(t, origOk)
			assert.Nil(t, origVault)
		})
	}
}
