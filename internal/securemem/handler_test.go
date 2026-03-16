package securemem_test

import (
	"context"
	"crypto/aes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/securemem"
)

func TestHandlerRequest(t *testing.T) {
	t.Run("HandlerRequest", func(t *testing.T) {
		// given when
		req := securemem.NewHandlerRequest()

		// then
		assert.NotNil(t, req)
		assert.NotNil(t, req.PersistentVault())
		assert.NotNil(t, req.TmpVault())
	})
}

func TestRun(t *testing.T) {
	t.Run("Run", func(t *testing.T) {
		t.Run("should not return error if handler returns no error", func(t *testing.T) {
			// given when
			resp, err := securemem.Run(t.Context(), func(ctx context.Context, req *securemem.HandlerRequest) error {
				return nil
			})

			// then
			assert.NoError(t, err)
			assert.NotNil(t, resp)
		})

		t.Run("should return error if handler returns an error", func(t *testing.T) {
			// given when
			resp, err := securemem.Run(t.Context(), func(ctx context.Context, req *securemem.HandlerRequest) error {
				return assert.AnError
			})

			// then
			assert.ErrorIs(t, err, assert.AnError)
			assert.Nil(t, resp)
		})

		t.Run("should return error if the context is canceled", func(t *testing.T) {
			// given
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			// when
			resp, err := securemem.Run(ctx, func(ctx context.Context, req *securemem.HandlerRequest) error {
				return nil
			})

			// then
			assert.ErrorIs(t, err, context.Canceled)
			assert.Nil(t, resp)
		})

		t.Run("should return error if the context is canceled after handler execution", func(t *testing.T) {
			// given
			ctx, cancel := context.WithCancel(t.Context())

			// when
			resp, err := securemem.Run(ctx, func(ctx context.Context, req *securemem.HandlerRequest) error {
				cancel()
				return nil
			})

			// then
			assert.ErrorIs(t, err, context.Canceled)
			assert.Nil(t, resp)
		})
	})
}

func TestHandlerRequestRun(t *testing.T) {
	t.Run("HandlerRequest in run", func(t *testing.T) {
		t.Run("should persist values in persistent vault", func(t *testing.T) {
			// given when
			resp, err := securemem.Run(t.Context(), func(ctx context.Context, req *securemem.HandlerRequest) error {
				b, err := req.PersistentVault().Reserve("foo", 3)
				copy(b, []byte("bar"))
				return err
			})

			// then
			assert.NoError(t, err)
			assert.NotNil(t, resp)

			actBytes, ok := resp.MemVault().Get("foo")
			assert.True(t, ok)
			assert.Equal(t, "bar", string(actBytes))
		})

		t.Run("should not persist values in tmp vault", func(t *testing.T) {
			// given when
			resp, err := securemem.Run(t.Context(), func(ctx context.Context, req *securemem.HandlerRequest) error {
				b, err := req.TmpVault().Reserve("foo", 3)
				copy(b, []byte("bar"))
				return err
			})

			// then
			assert.NoError(t, err)
			assert.NotNil(t, resp)

			actBytes, ok := resp.MemVault().Get("foo")
			assert.False(t, ok)
			assert.Nil(t, actBytes)
		})

		t.Run("should be able to access values in tmp vault during handler execution", func(t *testing.T) {
			// given when
			resp, err := securemem.Run(t.Context(), func(ctx context.Context, req *securemem.HandlerRequest) error {
				b, err := req.TmpVault().Reserve("foo", 3)
				if err != nil {
					return err
				}
				copy(b, []byte("bar"))

				actBytes, ok := req.TmpVault().Get("foo")
				assert.True(t, ok)
				assert.Equal(t, "bar", string(actBytes))
				return nil
			})

			// then
			assert.NoError(t, err)
			assert.NotNil(t, resp)
		})

		t.Run("should be able to access values in persistent vault during handler execution", func(t *testing.T) {
			// given when
			resp, err := securemem.Run(t.Context(), func(ctx context.Context, req *securemem.HandlerRequest) error {
				b, err := req.PersistentVault().Reserve("foo", 3)
				if err != nil {
					return err
				}
				copy(b, []byte("bar"))

				actBytes, ok := req.PersistentVault().Get("foo")
				assert.True(t, ok)
				assert.Equal(t, "bar", string(actBytes))
				return nil
			})

			// then
			assert.NoError(t, err)
			assert.NotNil(t, resp)
		})
	})
}

func BenchmarkMemVault_Reserve(b *testing.B) {
	for range b.N {
		b.ReportAllocs()
		resp, err := securemem.Run(b.Context(), func(ctx context.Context, hr *securemem.HandlerRequest) error {
			b := []byte("MYSECRETKEY123458901234567890123")
			secret, err := hr.PersistentVault().Reserve("secret", len(b))
			if err != nil {
				return err
			}
			copy(secret, b)

			tmpSecret, err := hr.TmpVault().Reserve("tmp_secret", len(b))
			if err != nil {
				return err
			}
			copy(tmpSecret, b)

			_, err = aes.NewCipher(b)
			if err != nil {
				panic(fmt.Sprintf("Failed to create AES cipher: %v", err))
			}

			return nil
		})
		assert.NoError(b, err)
		v, ok := resp.MemVault().Get("secret")
		assert.True(b, ok)
		assert.Equal(b, []byte("MYSECRETKEY123458901234567890123"), v)
		err = resp.MemVault().DestroyAll()
		assert.NoError(b, err)
	}
}
