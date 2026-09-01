package interceptor_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
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
		name        string
		allowedURIs []string
		expected    map[string]struct{}
		expErr      error
	}{
		{
			name:        "nil allowed URIs",
			allowedURIs: nil,
			expected:    nil,
			expErr:      interceptor.ErrNoAllowedURIs,
		},
		{
			name:        "empty allowed URIs",
			allowedURIs: []string{},
			expected:    nil,
			expErr:      interceptor.ErrNoAllowedURIs,
		},
		{
			name:        "single allowed URI",
			allowedURIs: []string{"client1"},
			expected:    map[string]struct{}{"client1": {}},
		},
		{
			name:        "multiple allowed URIs",
			allowedURIs: []string{"client1", "client2"},
			expected:    map[string]struct{}{"client1": {}, "client2": {}},
		},
		{
			name:        "duplicate allowed URIs",
			allowedURIs: []string{"client1", "client1"},
			expected:    map[string]struct{}{"client1": {}},
		},
		{
			name:        "allowed URIs with empty string",
			allowedURIs: []string{"client1", ""},
			expected:    map[string]struct{}{"client1": {}},
		},
		{
			name:        "allowed URIs with space characters",
			allowedURIs: []string{"     client1", "client2   "},
			expected:    map[string]struct{}{"client1": {}, "client2": {}},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			subj, err := interceptor.NewAuthenticator(tt.allowedURIs)

			// then
			assert.Equal(t, tt.expErr, err)
			if tt.expErr == nil {
				assert.Equal(t, tt.expected, interceptor.AllowedURIs(subj))
			} else {
				assert.Nil(t, subj)
			}
		})
	}
}

func TestUnaryInterceptor_NoAllowedURIs(t *testing.T) {
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
		allowedURIs    []string
		verifiedChains [][]*x509.Certificate
	}{
		{
			name:        "single allowed URI, unauthorized client",
			allowedURIs: []string{makeKryptonID("client1")},
			verifiedChains: [][]*x509.Certificate{
				{
					{URIs: makeURIs(t, "unauthorizedClient")},
				},
			},
		},
		{
			name:        "multiple allowed URIs, unauthorized client",
			allowedURIs: []string{makeKryptonID("client1"), makeKryptonID("client2")},
			verifiedChains: [][]*x509.Certificate{
				{
					{URIs: makeURIs(t, "unauthorizedClient")},
				},
			},
		},
		{
			name:        "multiple verified chains, unauthorized client",
			allowedURIs: []string{makeKryptonID("client1")},
			verifiedChains: [][]*x509.Certificate{
				{
					{URIs: makeURIs(t, "unauthorizedClient")},
				},
				{
					{URIs: makeURIs(t, "client1")},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// given
			auth, err := interceptor.NewAuthenticator(tt.allowedURIs)
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
	auth, err := interceptor.NewAuthenticator([]string{makeKryptonID("client1")})
	require.NoError(t, err)

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{URIs: makeURIs(t, "client1")},
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

func TestUnaryInterceptor_AuthorizedClientWithMultipleAllowedURIs(t *testing.T) {
	// given
	auth, err := interceptor.NewAuthenticator([]string{makeKryptonID("client1"), makeKryptonID("client2")})
	require.NoError(t, err)

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{URIs: makeURIs(t, "client2")},
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
	auth, err := interceptor.NewAuthenticator([]string{makeKryptonID("client1")})
	require.NoError(t, err)

	ctx := peer.NewContext(t.Context(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{
				VerifiedChains: [][]*x509.Certificate{
					{
						{URIs: makeURIs(t, "client1")},
					},
					{
						{URIs: makeURIs(t, "client2")},
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

func TestUnaryInterceptor_InvalidURICount(t *testing.T) {
	// given
	auth, err := interceptor.NewAuthenticator([]string{makeKryptonID("client1")})
	require.NoError(t, err)

	// https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#2-spiffe-id
	// An X.509 SVID MUST contain exactly one URI SAN.
	tts := []struct {
		name           string
		verifiedChains [][]*x509.Certificate
	}{
		{
			name: "zero URI SANs",
			verifiedChains: [][]*x509.Certificate{
				{
					{URIs: nil},
				},
			},
		},
		{
			name: "multiple URI SANs",
			verifiedChains: [][]*x509.Certificate{
				{
					{URIs: makeURIs(t, "client1", "client2")},
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := peer.NewContext(t.Context(), &peer.Peer{
				AuthInfo: credentials.TLSInfo{
					State: tls.ConnectionState{
						VerifiedChains: tt.verifiedChains,
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
			assert.Equal(t, codes.Unauthenticated, status.Code(err))
			assert.Nil(t, resp)
			assert.False(t, handlerCalled)
		})
	}
}

func makeKryptonID(uri string) string {
	return "kryptonid://acme-corp/service/" + uri
}

func makeURIs(t *testing.T, uris ...string) []*url.URL {
	t.Helper()
	result := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		parsed, err := url.Parse(makeKryptonID(u))
		require.NoError(t, err, "parse URI %s", u)
		result = append(result, parsed)
	}
	return result
}
