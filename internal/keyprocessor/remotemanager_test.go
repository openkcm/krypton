package keyprocessor_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
)

func TestNewRPCManager(t *testing.T) {
	t.Run("should return error when grpc connection is nil", func(t *testing.T) {
		// given

		// when
		mgr, err := keyprocessor.NewRPCManager(nil)

		// then
		assert.ErrorIs(t, err, keyprocessor.ErrNilGRPCConn)
		assert.Nil(t, mgr)
	})

	t.Run("should create a rpc manager from a valid grpc connection", func(t *testing.T) {
		// given
		target := "localhost:50051"
		conn, err := grpc.NewClient(
			target,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		// when
		mgr, err := keyprocessor.NewRPCManager(conn)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, mgr)
	})
}

func TestRPCManagerSeal(t *testing.T) {
	t.Run("should seal data successfully", func(t *testing.T) {
		// given
		client := &mockServiceClient{
			sealFn: func(_ context.Context, _ *sealer.SealRequest, _ ...grpc.CallOption) (*sealer.SealResponse, error) {
				return &sealer.SealResponse{Ciphertext: []byte("encrypted-payload")}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		resp, err := subj.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("secret payload")),
			AAD:        []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		require.NotNil(t, resp.Ciphertext)
		assert.Equal(t, []byte("encrypted-payload"), []byte(resp.Ciphertext.SecureBytes()))
	})

	t.Run("should pass correct request fields to gRPC client", func(t *testing.T) {
		// given
		var actTenantID, actKeyID string
		var actKeyVersion int32
		var actPlaintext, actAAD []byte

		client := &mockServiceClient{
			sealFn: func(_ context.Context, in *sealer.SealRequest, _ ...grpc.CallOption) (*sealer.SealResponse, error) {
				actTenantID = in.GetTenantId()
				actKeyID = in.GetKeyId()
				actKeyVersion = in.GetKeyVersion()
				// Copy plaintext — the underlying secure memory is destroyed after the handler returns.
				actPlaintext = append([]byte(nil), in.GetPlaintext()...)
				actAAD = in.GetAad()
				return &sealer.SealResponse{Ciphertext: []byte("ciphertext")}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		_, err := subj.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   "tenant-42",
			KeyID:      "key-99",
			KeyVersion: 7,
			Plaintext:  newTestData(t, []byte("my-secret")),
			AAD:        []byte("extra-context"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, "tenant-42", actTenantID)
		assert.Equal(t, "key-99", actKeyID)
		assert.Equal(t, int32(7), actKeyVersion)
		assert.Equal(t, []byte("my-secret"), actPlaintext)
		assert.Equal(t, []byte("extra-context"), actAAD)
	})

	t.Run("should return error when gRPC seal fails", func(t *testing.T) {
		// given
		sealErr := errors.New("rpc unavailable")
		client := &mockServiceClient{
			sealFn: func(_ context.Context, _ *sealer.SealRequest, _ ...grpc.CallOption) (*sealer.SealResponse, error) {
				return nil, sealErr
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		resp, err := subj.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("secret")),
		})

		// then
		assert.ErrorIs(t, err, sealErr)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should return error when gRPC returns empty ciphertext", func(t *testing.T) {
		// given
		client := &mockServiceClient{
			sealFn: func(_ context.Context, _ *sealer.SealRequest, _ ...grpc.CallOption) (*sealer.SealResponse, error) {
				return &sealer.SealResponse{}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		resp, err := subj.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("secret")),
		})

		// then
		assert.ErrorIs(t, err, securemem.ErrInvalidSize)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should return error when context is cancelled", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		client := &mockServiceClient{}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		resp, err := subj.Seal(ctx, cryptor.SealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("secret")),
		})

		// then
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should destroy input plaintext after successful seal", func(t *testing.T) {
		// given
		client := &mockServiceClient{
			sealFn: func(_ context.Context, _ *sealer.SealRequest, _ ...grpc.CallOption) (*sealer.SealResponse, error) {
				return &sealer.SealResponse{Ciphertext: []byte("ciphertext")}, nil
			},
		}
		plaintext := newTestData(t, []byte("destroy-me"))

		subj := keyprocessor.NewTestRPCManager(client)

		// when
		_, err := subj.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Plaintext:  plaintext,
		})

		// then
		assert.NoError(t, err)
		assert.Nil(t, plaintext.SecureBytes())
	})

	t.Run("should destroy input plaintext even when gRPC seal fails", func(t *testing.T) {
		// given
		client := &mockServiceClient{
			sealFn: func(_ context.Context, _ *sealer.SealRequest, _ ...grpc.CallOption) (*sealer.SealResponse, error) {
				return nil, errors.New("rpc error")
			},
		}
		plaintext := newTestData(t, []byte("destroy-me-too"))
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		_, err := subj.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Plaintext:  plaintext,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, plaintext.SecureBytes())
	})

	t.Run("should not panic when plaintext is nil", func(t *testing.T) {
		// given
		subj := keyprocessor.NewTestRPCManager(&mockServiceClient{})

		// when
		res, err := subj.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Plaintext:  nil,
		})

		// then
		assert.Error(t, err)
		assert.ErrorIs(t, err, keyprocessor.ErrNilSecureBytes)
		assert.Equal(t, cryptor.SealResponse{}, res)
	})

	t.Run("should zero gRPC response ciphertext after copy", func(t *testing.T) {
		ciphertextPayload := []byte("encrypted-payload")
		client := &mockServiceClient{
			sealFn: func(_ context.Context, _ *sealer.SealRequest, _ ...grpc.CallOption) (*sealer.SealResponse, error) {
				return &sealer.SealResponse{Ciphertext: ciphertextPayload}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		_, err := subj.Seal(t.Context(), cryptor.SealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("secret")),
		})

		assert.NoError(t, err)
		// The original slice returned by the mock should be zeroed by securemem.Zero
		assert.Equal(t, make([]byte, len(ciphertextPayload)), ciphertextPayload)
	})
}

func TestRPCManagerUnseal(t *testing.T) {
	t.Run("should unseal data successfully", func(t *testing.T) {
		// given
		client := &mockServiceClient{
			unsealFn: func(_ context.Context, _ *sealer.UnsealRequest, _ ...grpc.CallOption) (*sealer.UnsealResponse, error) {
				return &sealer.UnsealResponse{Plaintext: []byte("decrypted-payload")}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		resp, err := subj.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Ciphertext: newTestData(t, []byte("sealed-data")),
			AAD:        []byte("aad"),
		})

		// then
		assert.NoError(t, err)
		require.NotNil(t, resp.Plaintext)
		assert.Equal(t, []byte("decrypted-payload"), []byte(resp.Plaintext.SecureBytes()))
	})

	t.Run("should pass correct request fields to gRPC client", func(t *testing.T) {
		// given
		var actTenantID, actKeyID string
		var actKeyVersion int32
		var actCiphertext, actAAD []byte

		client := &mockServiceClient{
			unsealFn: func(_ context.Context, in *sealer.UnsealRequest, _ ...grpc.CallOption) (*sealer.UnsealResponse, error) {
				actTenantID = in.GetTenantId()
				actKeyID = in.GetKeyId()
				actKeyVersion = in.GetKeyVersion()
				// Copy ciphertext — the underlying secure memory is destroyed after the handler returns.
				actCiphertext = append([]byte(nil), in.GetCiphertext()...)
				actAAD = in.GetAad()
				return &sealer.UnsealResponse{Plaintext: []byte("plaintext")}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		_, err := subj.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   "tenant-42",
			KeyID:      "key-99",
			KeyVersion: 7,
			Ciphertext: newTestData(t, []byte("my-ciphertext")),
			AAD:        []byte("extra-context"),
		})

		// then
		assert.NoError(t, err)
		assert.Equal(t, "tenant-42", actTenantID)
		assert.Equal(t, "key-99", actKeyID)
		assert.Equal(t, int32(7), actKeyVersion)
		assert.Equal(t, []byte("my-ciphertext"), actCiphertext)
		assert.Equal(t, []byte("extra-context"), actAAD)
	})

	t.Run("should return error when gRPC unseal fails", func(t *testing.T) {
		// given
		unsealErr := errors.New("rpc unavailable")
		client := &mockServiceClient{
			unsealFn: func(_ context.Context, _ *sealer.UnsealRequest, _ ...grpc.CallOption) (*sealer.UnsealResponse, error) {
				return nil, unsealErr
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		resp, err := subj.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Ciphertext: newTestData(t, []byte("sealed")),
		})

		// then
		assert.ErrorIs(t, err, unsealErr)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})

	t.Run("should return error when gRPC returns empty plaintext", func(t *testing.T) {
		// given
		client := &mockServiceClient{
			unsealFn: func(_ context.Context, _ *sealer.UnsealRequest, _ ...grpc.CallOption) (*sealer.UnsealResponse, error) {
				return &sealer.UnsealResponse{}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		resp, err := subj.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Ciphertext: newTestData(t, []byte("sealed")),
		})

		// then
		assert.ErrorIs(t, err, securemem.ErrInvalidSize)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})

	t.Run("should return error when context is cancelled", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		client := &mockServiceClient{}
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		resp, err := subj.Unseal(ctx, cryptor.UnsealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Ciphertext: newTestData(t, []byte("sealed")),
		})

		// then
		assert.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})

	t.Run("should destroy input ciphertext after successful unseal", func(t *testing.T) {
		// given
		client := &mockServiceClient{
			unsealFn: func(_ context.Context, _ *sealer.UnsealRequest, _ ...grpc.CallOption) (*sealer.UnsealResponse, error) {
				return &sealer.UnsealResponse{Plaintext: []byte("plaintext")}, nil
			},
		}
		ciphertext := newTestData(t, []byte("destroy-me"))
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		_, err := subj.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Ciphertext: ciphertext,
		})

		// then
		assert.NoError(t, err)
		assert.Nil(t, ciphertext.SecureBytes())
	})

	t.Run("should destroy input ciphertext even when gRPC unseal fails", func(t *testing.T) {
		// given
		client := &mockServiceClient{
			unsealFn: func(_ context.Context, _ *sealer.UnsealRequest, _ ...grpc.CallOption) (*sealer.UnsealResponse, error) {
				return nil, errors.New("rpc error")
			},
		}
		ciphertext := newTestData(t, []byte("destroy-me-too"))
		subj := keyprocessor.NewTestRPCManager(client)

		// when
		_, err := subj.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Ciphertext: ciphertext,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, ciphertext.SecureBytes())
	})

	t.Run("should not panic when ciphertext is nil", func(t *testing.T) {
		// given
		subj := keyprocessor.NewTestRPCManager(&mockServiceClient{})

		// when
		res, err := subj.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Ciphertext: nil,
		})

		// then
		assert.Error(t, err)
		assert.ErrorIs(t, err, keyprocessor.ErrNilSecureBytes)
		assert.Equal(t, cryptor.UnsealResponse{}, res)
	})

	t.Run("should zero gRPC response plaintext after copy", func(t *testing.T) {
		plaintextPayload := []byte("decrypted-payload")
		client := &mockServiceClient{
			unsealFn: func(_ context.Context, _ *sealer.UnsealRequest, _ ...grpc.CallOption) (*sealer.UnsealResponse, error) {
				return &sealer.UnsealResponse{Plaintext: plaintextPayload}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		_, err := subj.Unseal(t.Context(), cryptor.UnsealRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Ciphertext: newTestData(t, []byte("sealed")),
		})

		assert.NoError(t, err)
		// The original slice returned by the mock should be zeroed by securemem.Zero
		assert.Equal(t, make([]byte, len(plaintextPayload)), plaintextPayload)
	})
}

func TestConcurrentSealUnseal(t *testing.T) {
	t.Run("should handle concurrent seal and unseal calls", func(t *testing.T) {
		client := &mockServiceClient{
			sealFn: func(_ context.Context, _ *sealer.SealRequest, _ ...grpc.CallOption) (*sealer.SealResponse, error) {
				return &sealer.SealResponse{Ciphertext: []byte("ciphertext")}, nil
			},
			unsealFn: func(_ context.Context, _ *sealer.UnsealRequest, _ ...grpc.CallOption) (*sealer.UnsealResponse, error) {
				return &sealer.UnsealResponse{Plaintext: []byte("plaintext")}, nil
			},
		}
		subj := keyprocessor.NewTestRPCManager(client)

		const goroutines = 10
		var wg sync.WaitGroup
		errs := make([]error, goroutines*2)

		for i := range goroutines {
			wg.Go(func() {
				_, errs[i] = subj.Seal(t.Context(), cryptor.SealRequest{
					TenantID:   "tenant-1",
					KeyID:      "key-1",
					KeyVersion: 1,
					Plaintext:  newTestData(t, []byte("secret")),
				})
			})
		}

		for i := range goroutines {
			wg.Go(func() {
				_, errs[goroutines+i] = subj.Unseal(t.Context(), cryptor.UnsealRequest{
					TenantID:   "tenant-1",
					KeyID:      "key-1",
					KeyVersion: 1,
					Ciphertext: newTestData(t, []byte("sealed")),
				})
			})
		}

		wg.Wait()

		for i, err := range errs {
			assert.NoError(t, err, "goroutine %d failed", i)
		}
	})
}

// mockServiceClient implements sealer.ServiceClient for testing RPCManager
// without a real gRPC connection.
type mockServiceClient struct {
	sealFn   func(ctx context.Context, in *sealer.SealRequest, opts ...grpc.CallOption) (*sealer.SealResponse, error)
	unsealFn func(ctx context.Context, in *sealer.UnsealRequest, opts ...grpc.CallOption) (*sealer.UnsealResponse, error)
}

func (m *mockServiceClient) Seal(ctx context.Context, in *sealer.SealRequest, opts ...grpc.CallOption) (*sealer.SealResponse, error) {
	return m.sealFn(ctx, in, opts...)
}

func (m *mockServiceClient) Unseal(ctx context.Context, in *sealer.UnsealRequest, opts ...grpc.CallOption) (*sealer.UnsealResponse, error) {
	return m.unsealFn(ctx, in, opts...)
}
