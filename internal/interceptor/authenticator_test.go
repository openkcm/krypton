package interceptor_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/interceptor"
)

func TestNewAuthenticator(t *testing.T) {
	// given
	tts := []struct {
		name       string
		allowedCNs []string
		expected   map[string]struct{}
		expErr     error
	}{
		{
			name:       "nil allowed CNs",
			allowedCNs: nil,
			expected:   nil,
			expErr:     interceptor.ErrNoAllowedCNs,
		},
		{
			name:       "empty allowed CNs",
			allowedCNs: []string{},
			expected:   nil,
			expErr:     interceptor.ErrNoAllowedCNs,
		},
		{
			name:       "single allowed CN",
			allowedCNs: []string{"client1"},
			expected:   map[string]struct{}{"client1": {}},
		},
		{
			name:       "multiple allowed CNs",
			allowedCNs: []string{"client1", "client2"},
			expected:   map[string]struct{}{"client1": {}, "client2": {}},
		},
		{
			name:       "duplicate allowed CNs",
			allowedCNs: []string{"client1", "client1"},
			expected:   map[string]struct{}{"client1": {}},
		},
		{
			name:       "allowed CNs with empty string",
			allowedCNs: []string{"client1", ""},
			expected:   map[string]struct{}{"client1": {}},
		},
		{
			name:       "allowed CNs with space characters",
			allowedCNs: []string{"     client1", "client2   "},
			expected:   map[string]struct{}{"client1": {}, "client2": {}},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			subj, err := interceptor.NewAuthenticator(tt.allowedCNs)

			// then
			assert.Equal(t, tt.expErr, err)
			if tt.expErr == nil {
				assert.Equal(t, tt.expected, interceptor.AllowedCNs(subj))
			} else {
				assert.Nil(t, subj)
			}
		})
	}
}

func TestUnaryInterceptor_NoAllowedCNs(t *testing.T) {
	// given
	auth := interceptor.Authenticator{}

	// when
	_, err := auth.UnaryInterceptor(t.Context(), nil, nil, nil)

	// then
	assert.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestUnaryInterceptor_NoPeerInfo(t *testing.T) {
	// given
	auth, err := interceptor.NewAuthenticator([]string{"client1"})
	require.NoError(t, err)

	// when
	_, err = auth.UnaryInterceptor(t.Context(), nil, nil, nil)

	// then
	assert.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUnaryInterceptor_NoTLSInfo(t *testing.T) {
	// given
	auth, err := interceptor.NewAuthenticator([]string{"client1"})
	require.NoError(t, err)

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: nil, // or some non-TLS AuthInfo
	})

	// when
	_, err = auth.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, nil)

	// then
	assert.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUnaryInterceptor_NoVerifiedChains(t *testing.T) {
	// given
	auth, err := interceptor.NewAuthenticator([]string{"client1"})
	require.NoError(t, err)

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: nil,
			},
		},
	})

	// when
	_, err = auth.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, nil)

	// then
	assert.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUnaryInterceptor_UnauthorizedClient(t *testing.T) {
	// given
	tts := []struct {
		name           string
		allowedCNs     []string
		verifiedChains [][]*x509.Certificate
	}{
		{
			name:       "single allowed CN, unauthorized client",
			allowedCNs: []string{"client1"},
			verifiedChains: [][]*x509.Certificate{
				{
					{Subject: pkix.Name{CommonName: "unauthorizedClient"}},
				},
			},
		},
		{
			name:       "multiple allowed CNs, unauthorized client",
			allowedCNs: []string{"client1", "client2"},
			verifiedChains: [][]*x509.Certificate{
				{
					{Subject: pkix.Name{CommonName: "unauthorizedClient"}},
				},
			},
		},
		{
			name:       "multiple verified chains, unauthorized client",
			allowedCNs: []string{"client1"},
			verifiedChains: [][]*x509.Certificate{
				{
					{Subject: pkix.Name{CommonName: "unauthorizedClient"}},
				},
				{
					{Subject: pkix.Name{CommonName: "client1"}},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// given
			auth, err := interceptor.NewAuthenticator(tt.allowedCNs)
			require.NoError(t, err)

			ctx := peer.NewContext(t.Context(), &peer.Peer{
				AuthInfo: credentials.TLSInfo{
					State: tls.ConnectionState{
						VerifiedChains: tt.verifiedChains,
					},
				},
			})

			// when
			_, err = auth.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, nil)

			// then
			assert.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
}

func TestUnaryInterceptor_AuthorizedClient(t *testing.T) {
	// given
	auth, err := interceptor.NewAuthenticator([]string{"client1"})
	require.NoError(t, err)

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{Subject: pkix.Name{CommonName: "client1"}},
					},
				},
			},
		},
	})

	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return "response", nil
	}

	// when
	resp, err := auth.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)

	// then
	assert.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handlerCalled)
}

func TestUnaryInterceptor_AuthorizedClientWithMultipleAllowedCNs(t *testing.T) {
	// given
	auth, err := interceptor.NewAuthenticator([]string{"client1", "client2"})
	require.NoError(t, err)

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{Subject: pkix.Name{CommonName: "client2"}},
					},
				},
			},
		},
	})

	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return "response", nil
	}

	// when
	resp, err := auth.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)

	// then
	assert.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handlerCalled)
}

func TestUnaryInterceptor_AuthorizedClientWithMultipleVerifiedChains(t *testing.T) {
	// given
	auth, err := interceptor.NewAuthenticator([]string{"client1"})
	require.NoError(t, err)

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{Subject: pkix.Name{CommonName: "client1"}},
					},
					{
						{Subject: pkix.Name{CommonName: "client2"}},
					},
				},
			},
		},
	})

	handlerCalled := false
	handler := func(ctx context.Context, req any) (any, error) {
		handlerCalled = true
		return "response", nil
	}

	// when
	resp, err := auth.UnaryInterceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/test/Method"}, handler)

	// then
	assert.NoError(t, err)
	assert.Equal(t, "response", resp)
	assert.True(t, handlerCalled)
}
