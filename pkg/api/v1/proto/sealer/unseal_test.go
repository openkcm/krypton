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

func TestUnsealer(t *testing.T) {
	t.Run("should unseal ciphertext successfully", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		expTenantID := uuid.New().String()
		expKeyID := uuid.New().String()
		expKeyVersion := 1
		expCiphertext := []byte("test ciphertext")
		expAad := []byte("test aad")
		expRespBytes := []byte("actual plaintext")

		actReqCiphertext := make([]byte, len(expCiphertext))
		var actReq cryptor.UnsealRequest
		mgr.FnUnseal = func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			actReq = req
			copy(actReqCiphertext, req.Ciphertext.SecureBytes())

			cData, err := securemem.NewData("resp", len(expRespBytes))
			require.NoError(t, err)

			t.Cleanup(func() {
				cData.Destroy()
			})

			copy(cData.SecureBytes(), expRespBytes)

			return cryptor.UnsealResponse{
				Plaintext: cData,
			}, nil
		}

		cli := newSealerClient(t, mgr)

		// when
		actRes, err := cli.Unseal(ctx, &sealer.UnsealRequest{
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

	t.Run("should return invalid argument error for invalid requests", func(t *testing.T) {
		validTenantID := uuid.New().String()
		validKeyID := uuid.New().String()
		validKeyVersion := int32(1)
		validCiphertext := []byte("test ciphertext")
		validAad := []byte("test aad")

		tests := []struct {
			name   string
			req    *sealer.UnsealRequest
			expErr error
		}{
			{
				name: "missing tenant ID",
				req: &sealer.UnsealRequest{
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidTenantID,
			},
			{
				name: "missing key ID",
				req: &sealer.UnsealRequest{
					TenantId:   validTenantID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidKeyID,
			},
			{
				name: "zero key version",
				req: &sealer.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidKeyVersion,
			},
			{
				name: "negative key version",
				req: &sealer.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: -1,
					Ciphertext: validCiphertext,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidKeyVersion,
			},
			{
				name: "nil ciphertext",
				req: &sealer.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidCiphertext,
			},
			{
				name: "empty ciphertext",
				req: &sealer.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: []byte{},
					Aad:        validAad,
				},
				expErr: sealer.ErrInvalidCiphertext,
			},
			{
				name: "nil AAD",
				req: &sealer.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
				},
				expErr: sealer.ErrInvalidAAD,
			},
			{
				name: "empty AAD",
				req: &sealer.UnsealRequest{
					TenantId:   validTenantID,
					KeyId:      validKeyID,
					KeyVersion: validKeyVersion,
					Ciphertext: validCiphertext,
					Aad:        []byte{},
				},
				expErr: sealer.ErrInvalidAAD,
			},
			{
				name: "all fields missing",
				req:  &sealer.UnsealRequest{},
				expErr: errors.Join(
					sealer.ErrInvalidTenantID,
					sealer.ErrInvalidKeyID,
					sealer.ErrInvalidKeyVersion,
					sealer.ErrInvalidCiphertext,
					sealer.ErrInvalidAAD,
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

		expTenantID := uuid.New().String()
		expKeyID := uuid.New().String()
		expKeyVersion := 1
		expCiphertext := []byte("test cipher")
		expAad := []byte("test aad")

		mgr.FnUnseal = func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			return cryptor.UnsealResponse{}, assert.AnError
		}

		cli := newSealerClient(t, mgr)

		// when
		actRes, err := cli.Unseal(ctx, &sealer.UnsealRequest{
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
}
