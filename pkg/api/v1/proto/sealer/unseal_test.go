package sealer_test

import (
	"context"
	"errors"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	sealergrpc "github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
)

func TestUnsealer(t *testing.T) {
	expTenantID := uuid.New().String()
	expKeyID := uuid.New().String()
	expKeyVersion := 1
	expCiphertext := []byte("test ciphertext")
	expAad := []byte("test aad")
	expRespBytes := []byte("actual plaintext")

	t.Run("should unseal ciphertext successfully", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		actReqCiphertext := make([]byte, len(expCiphertext))
		var actReq sealer.UnsealRequest
		mgr.FnUnseal = func(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
			actReq = req
			copy(actReqCiphertext, req.Ciphertext.SecureBytes())

			cData, err := securemem.NewData("resp", len(expRespBytes))
			require.NoError(t, err)

			t.Cleanup(func() {
				cData.Destroy()
			})

			copy(cData.SecureBytes(), expRespBytes)

			return sealer.UnsealResponse{
				Plaintext: cData,
			}, nil
		}

		cli := newSealerClientWithRPCHandler(t, mgr)

		// when
		actRes, err := cli.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Ciphertext: expCiphertext,
			Aad:        expAad,
		})

		// then
		require.NoError(t, err)
		assert.Equal(t, expRespBytes, actRes.GetPlaintext())

		assert.Equal(t, expTenantID, actReq.TenantID)
		assert.Equal(t, expKeyID, actReq.KeyID)
		assert.Equal(t, expKeyVersion, actReq.KeyVersion)
		assert.Equal(t, expCiphertext, actReqCiphertext)
		assert.Equal(t, expAad, actReq.AAD)
	})

	t.Run("should destroy secure memory after RPC completes", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		cData, err := securemem.NewData("resp", len(expRespBytes))
		require.NoError(t, err)

		t.Cleanup(func() {
			cData.Destroy()
		})

		mgr.FnUnseal = func(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
			copy(cData.SecureBytes(), expRespBytes)

			return sealer.UnsealResponse{
				Plaintext: cData,
			}, nil
		}

		cli := newSealerClientWithRPCHandler(t, mgr)

		// when
		actRes, err := cli.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Ciphertext: expCiphertext,
			Aad:        expAad,
		})

		// then
		require.NoError(t, err)
		assert.Equal(t, expRespBytes, actRes.GetPlaintext())

		assert.Nil(t, cData.SecureBytes(), "expected the secure memory to be destroyed after the RPC")
	})

	t.Run("should return invalid argument error for invalid requests", func(t *testing.T) {
		validTenantID := uuid.New().String()
		validKeyID := uuid.New().String()
		validKeyVersion := int32(1)
		validCiphertext := []byte("test ciphertext")
		validAad := []byte("test aad")

		tests := []struct {
			name   string
			req    *sealergrpc.UnsealRequest
			expErr error
		}{
			{
				name: "missing tenant ID",
				req: &sealergrpc.UnsealRequest{
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealergrpc.ErrInvalidTenantID,
			},
			{
				name: "invalid tenant ID format",
				req: &sealergrpc.UnsealRequest{
					TenantId:   "not-a-uuid",
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealergrpc.ErrInvalidTenantID,
			},
			{
				name: "missing key ID",
				req: &sealergrpc.UnsealRequest{
					TenantId:   validTenantID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealergrpc.ErrInvalidKeyID,
			},
			{
				name: "invalid key ID format",
				req: &sealergrpc.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      "not-a-uuid",
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealergrpc.ErrInvalidKeyID,
			},
			{
				name: "zero key version",
				req: &sealergrpc.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealergrpc.ErrInvalidKeyVersion,
			},
			{
				name: "negative key version",
				req: &sealergrpc.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: -1,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealergrpc.ErrInvalidKeyVersion,
			},
			{
				name: "nil ciphertext",
				req: &sealergrpc.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Aad:        validAad,
				},
				expErr: sealergrpc.ErrInvalidText,
			},
			{
				name: "empty ciphertext",
				req: &sealergrpc.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: []byte{},
					Aad:        validAad,
				},
				expErr: sealergrpc.ErrInvalidText,
			},
			{
				name: "nil AAD",
				req: &sealergrpc.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
				},
				expErr: sealergrpc.ErrInvalidAAD,
			},
			{
				name: "empty AAD",
				req: &sealergrpc.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
					Aad:        []byte{},
				},
				expErr: sealergrpc.ErrInvalidAAD,
			},
			{
				name: "all fields missing",
				req:  &sealergrpc.UnsealRequest{},
				expErr: errors.Join(
					sealergrpc.ErrInvalidTenantID,
					sealergrpc.ErrInvalidKeyID,
					sealergrpc.ErrInvalidKeyVersion,
					sealergrpc.ErrInvalidText,
					sealergrpc.ErrInvalidAAD,
				),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// given
				ctx := t.Context()
				mgr := newMockManager(t) // default FnUnseal fails the test if called
				cli := newSealerClient(t, mgr)

				// when
				actRes, err := cli.Unseal(ctx, tt.req)

				// then
				assert.Error(t, err)
				assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
				assert.Equal(t, tt.expErr.Error(), status.Convert(err).Message())
				assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
				assert.Nil(t, actRes)
			})
		}
	})

	t.Run("should return internal error when unsealing fails", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		mgr.FnUnseal = func(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
			return sealer.UnsealResponse{}, assert.AnError
		}

		cli := newSealerClientWithRPCHandler(t, mgr)

		// when
		actRes, err := cli.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Ciphertext: expCiphertext,
			Aad:        expAad,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assert.Equal(t, "failed to unseal the ciphertext", status.Convert(err).Message())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)

		assert.Nil(t, actRes)
	})

	t.Run("should return internal error when RPCHandler is not configured", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		mgr.FnUnseal = func(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
			pData, err := securemem.NewData("resp", len(expRespBytes))
			require.NoError(t, err)

			t.Cleanup(func() {
				pData.Destroy()
			})

			copy(pData.SecureBytes(), expRespBytes)

			return sealer.UnsealResponse{
				Plaintext: pData,
			}, nil
		}

		// client without RPCHandler — context will not contain a vault
		cli := newSealerClient(t, mgr)

		// when
		actRes, err := cli.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Ciphertext: expCiphertext,
			Aad:        expAad,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assert.Equal(t, "failed to get the vault from the context", status.Convert(err).Message())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)

		assert.Nil(t, actRes)
	})

	t.Run("should cleanup secure memory when RPCHandler is not configured", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		pData, err := securemem.NewData("resp", len(expRespBytes))
		require.NoError(t, err)

		t.Cleanup(func() {
			pData.Destroy()
		})
		mgr.FnUnseal = func(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
			copy(pData.SecureBytes(), expRespBytes)

			return sealer.UnsealResponse{
				Plaintext: pData,
			}, nil
		}

		// client without RPCHandler — context will not contain a vault
		cli := newSealerClient(t, mgr)

		// when
		actRes, err := cli.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   expTenantID,
			KeyId:      expKeyID,
			KeyVersion: int32(expKeyVersion),
			Ciphertext: expCiphertext,
			Aad:        expAad,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, actRes)

		assert.Nil(t, pData.SecureBytes(), "expected to be destroyed if there is an error adding to context vault")
	})
}
