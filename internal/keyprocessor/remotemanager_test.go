package keyprocessor_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
)

func TestNewRPCManager(t *testing.T) {
	t.Run("should succeed with nil TLS config (insecure)", func(t *testing.T) {
		// given
		target := "localhost:50051"

		// when
		mgr, err := keyprocessor.NewRPCManager(target, nil)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, mgr)
	})

	t.Run("should return error for unsupported auth config type", func(t *testing.T) {
		// given
		target := "localhost:50051"
		tlsCfg := &unsupportedAuthConfig{}

		// when
		mgr, err := keyprocessor.NewRPCManager(target, tlsCfg)

		// then
		assert.ErrorIs(t, err, config.ErrUnknownAuthType)
		assert.Nil(t, mgr)
	})

	t.Run("should return error when client cert file does not exist", func(t *testing.T) {
		// given
		target := "localhost:50051"
		tlsCfg := &config.MTLSConfig{
			Client: config.TLSClient{
				CertPath: "/nonexistent/client-cert.pem",
				KeyPath:  "/nonexistent/client-key.pem",
				CAPath:   "/nonexistent/ca.pem",
			},
		}

		// when
		mgr, err := keyprocessor.NewRPCManager(target, tlsCfg)

		// then
		assert.Error(t, err)
		assert.Nil(t, mgr)
	})

	t.Run("should return error when CA file contains invalid PEM", func(t *testing.T) {
		// given
		target := "localhost:50051"
		dir := t.TempDir()

		certPEM, keyPEM := generateSelfSignedCert(t)
		certPath := filepath.Join(dir, "client-cert.pem")
		keyPath := filepath.Join(dir, "client-key.pem")
		caPath := filepath.Join(dir, "ca.pem")

		require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
		require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))
		require.NoError(t, os.WriteFile(caPath, []byte("not a certificate"), 0o600))

		tlsCfg := &config.MTLSConfig{
			Client: config.TLSClient{
				CertPath: certPath,
				KeyPath:  keyPath,
				CAPath:   caPath,
			},
		}

		// when
		mgr, err := keyprocessor.NewRPCManager(target, tlsCfg)

		// then
		assert.ErrorIs(t, err, config.ErrCAInvalid)
		assert.Nil(t, mgr)
	})

	t.Run("should succeed with valid mTLS config", func(t *testing.T) {
		// given
		target := "localhost:50051"
		tlsCfg := newTestMTLSConfig(t)

		// when
		mgr, err := keyprocessor.NewRPCManager(target, tlsCfg)

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

// unsupportedAuthConfig is a config.AuthConfig that is not *config.MTLSConfig,
// causing config.GetAuthConfig to return config.ErrUnknownAuthType.
type unsupportedAuthConfig struct{}

func (u *unsupportedAuthConfig) AuthType() config.AuthType { return "unsupported" }
func (u *unsupportedAuthConfig) Validate() error           { return nil }

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

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

// newTestMTLSConfig generates a self-signed CA, a client keypair signed by that
// CA, and writes them to a temp directory. It returns a valid *config.MTLSConfig
// that will pass BuildTLSConfig.
func newTestMTLSConfig(t *testing.T) *config.MTLSConfig {
	t.Helper()
	dir := t.TempDir()

	// Generate CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	// Generate client cert signed by CA.
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)
	clientTmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTmpl, caCert, &clientKey.PublicKey, caKey)
	require.NoError(t, err)
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})

	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	require.NoError(t, err)
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: clientKeyDER})

	// Write files.
	certPath := filepath.Join(dir, "client-cert.pem")
	keyPath := filepath.Join(dir, "client-key.pem")
	caPath := filepath.Join(dir, "ca.pem")

	require.NoError(t, os.WriteFile(certPath, clientCertPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, clientKeyPEM, 0o600))
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	return &config.MTLSConfig{
		Client: config.TLSClient{
			CertPath: certPath,
			KeyPath:  keyPath,
			CAPath:   caPath,
		},
	}
}

// generateSelfSignedCert generates a self-signed certificate and private key
// for use in tests that need valid cert+key files but an invalid CA.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "self-signed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}
