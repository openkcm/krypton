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

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
)

func TestSealer(t *testing.T) {
	expTenantID := uuid.New().String()
	expKeyID := uuid.New().String()
	expKeyVersion := 1
	expPlaintext := []byte("test plaintext")
	expAad := []byte("test aad")
	expRespBytes := []byte("actual ciphertext")

	t.Run("should seal plaintext successfully", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

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

		cli := newSealerClientWithRPCHandler(t, mgr)

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

	t.Run("should destroy secure memory after RPC completes", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		cData, err := securemem.NewData("resp", len(expRespBytes))
		require.NoError(t, err)

		t.Cleanup(func() {
			cData.Destroy()
		})
		mgr.FnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			copy(cData.SecureBytes(), expRespBytes)

			return cryptor.SealResponse{
				Ciphertext: cData,
			}, nil
		}

		cli := newSealerClientWithRPCHandler(t, mgr)

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

		assert.Nil(t, cData.SecureBytes(), "expected the secure memory to be destroyed after the RPC")
	})

	t.Run("should return invalid argument error for invalid requests", func(t *testing.T) {
		validTenantID := uuid.New().String()
		validKeyID := uuid.New().String()
		validKeyVersion := int32(1)
		validPlaintext := []byte("test plaintext")
		validAad := []byte("test aad")

		tests := []struct {
			name   string
			req    *sealer.SealRequest
			expErr error
		}{
			{
				name: "missing tenant ID",
				req: &sealer.SealRequest{
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Plaintext:  validPlaintext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidTenantID,
			},
			{
				name: "invalid tenant ID format",
				req: &sealer.SealRequest{
					TenantId:   "not-a-uuid",
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Plaintext:  validPlaintext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidTenantID,
			},
			{
				name: "missing key ID",
				req: &sealer.SealRequest{
					TenantId:   validTenantID,
					KeyVersion: validKeyVersion,
					Plaintext:  validPlaintext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidKeyID,
			},
			{
				name: "invalid key ID format",
				req: &sealer.SealRequest{
					TenantId:   validTenantID,
					KeyId:      "not-a-uuid",
					KeyVersion: validKeyVersion,
					Plaintext:  validPlaintext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidKeyID,
			},
			{
				name: "zero key version",
				req: &sealer.SealRequest{
					TenantId:  validTenantID,
					KeyId:     validKeyID,
					Plaintext: validPlaintext,
					Aad:       validAad,
				},
				expErr: sealer.ErrInvalidKeyVersion,
			},
			{
				name: "negative key version",
				req: &sealer.SealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: -1,
					Plaintext:  validPlaintext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidKeyVersion,
			},
			{
				name: "nil plaintext",
				req: &sealer.SealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidText,
			},
			{
				name: "empty plaintext",
				req: &sealer.SealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Plaintext:  []byte{},
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidText,
			},
			{
				name: "nil AAD",
				req: &sealer.SealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Plaintext:  validPlaintext,
				},
				expErr: sealer.ErrInvalidAAD,
			},
			{
				name: "empty AAD",
				req: &sealer.SealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Plaintext:  validPlaintext,
					Aad:        []byte{},
				},
				expErr: sealer.ErrInvalidAAD,
			},
			{
				name: "all fields missing",
				req:  &sealer.SealRequest{},
				expErr: errors.Join(
					sealer.ErrInvalidTenantID,
					sealer.ErrInvalidKeyID,
					sealer.ErrInvalidKeyVersion,
					sealer.ErrInvalidText,
					sealer.ErrInvalidAAD,
				),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// given
				ctx := t.Context()
				mgr := newMockManager(t) // default FnSeal fails the test if called
				cli := newSealerClient(t, mgr)

				// when
				actRes, err := cli.Seal(ctx, tt.req)

				// then
				assert.Error(t, err)
				assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
				assert.Equal(t, tt.expErr.Error(), status.Convert(err).Message())
				assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
				assert.Nil(t, actRes)
			})
		}
	})

	t.Run("should return internal error when sealing fails", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		mgr.FnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			return cryptor.SealResponse{}, assert.AnError
		}

		cli := newSealerClientWithRPCHandler(t, mgr)

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

	t.Run("should return internal error when RPCHandler is not configured", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		mgr.FnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
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

		// client without RPCHandler — context will not contain a vault
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
		assert.Equal(t, "failed to get the vault from the context", status.Convert(err).Message())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)

		assert.Nil(t, actRes)
	})

	t.Run("should cleanup secure memory when RPCHandler is not configured", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		cData, err := securemem.NewData("resp", len(expRespBytes))
		require.NoError(t, err)

		t.Cleanup(func() {
			cData.Destroy()
		})

		copy(cData.SecureBytes(), expRespBytes)
		mgr.FnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			return cryptor.SealResponse{
				Ciphertext: cData,
			}, nil
		}

		// client without RPCHandler — context will not contain a vault
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
		assert.Nil(t, actRes)

		assert.Nil(t, cData.SecureBytes(), "expected to be destroyed if there is an error adding to context vault")
	})
}
