package sealer_test

import (
	"context"
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

	t.Run("should track input and output in vault", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		expTenantID := uuid.New().String()
		expKeyID := uuid.New().String()
		expKeyVersion := 1
		expCiphertext := []byte("test cipher")
		expAad := []byte("test aad")

		var actVault *securemem.MemVault
		mgr.FnUnseal = func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			vault, ok := sealer.VaultFromContext(ctx) // ensure vault is in context
			require.True(t, ok)
			actVault = vault

			expRespBytes := []byte("actual plain")
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
		assert.NotNil(t, actRes)

		// check context value
		_, ok := actVault.Get("input")
		assert.True(t, ok)
		_, ok = actVault.Get("output")
		assert.True(t, ok)

		err = actVault.DestroyAll()
		assert.NoError(t, err)
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

	t.Run("should return internal error when vault import fails", func(t *testing.T) {
		// given
		ctx := t.Context()

		mgr := newMockManager(t)

		expTenantID := uuid.New().String()
		expKeyID := uuid.New().String()
		expKeyVersion := 1
		expCiphertext := []byte("test cipher")
		expAad := []byte("test aad")

		plaintext, err := securemem.NewData("output", 10)
		require.NoError(t, err)

		t.Cleanup(func() {
			plaintext.Destroy()
		})

		copy(plaintext.SecureBytes(), []byte("plaintext"))

		mgr.FnUnseal = func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			vault, ok := sealer.VaultFromContext(ctx) // ensure vault is in context
			require.True(t, ok)

			data, err := securemem.NewData("output", 10)
			require.NoError(t, err)
			t.Cleanup(func() {
				data.Destroy()
			})

			require.NoError(t, vault.Import("output", data)) // simulate import failure

			return cryptor.UnsealResponse{
				Plaintext: plaintext,
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
		assert.Error(t, err)
		assert.Equal(t, codes.Internal, status.Code(err), err.Error())
		assert.Equal(t, "failed to import the plaintext into the vault", status.Convert(err).Message())
		assertErrorDetails(t, proto.Code_ERROR_CODE_ABORT, err)
		assert.Nil(t, plaintext.SecureBytes()) // ensure plaintext is destroyed on import failure

		assert.Nil(t, actRes)
	})
}
