package authz_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/authz"
	"github.com/openkcm/krypton/internal/spec"
)

// contextWithKryptonID creates a context with mocked peer TLS info containing the given KryptonID in URI SAN.
func contextWithKryptonID(t *testing.T, id spec.KryptonID) context.Context {
	t.Helper()

	uri, err := url.Parse(id.URI())
	assert.NoError(t, err)

	cert := &x509.Certificate{
		URIs: []*url.URL{uri},
	}
	tlsInfo := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}
	p := &peer.Peer{
		Addr:     &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
		AuthInfo: tlsInfo,
	}
	return peer.NewContext(context.Background(), p)
}

// mockServerStream implements grpc.ServerStream for testing.
type mockServerStream struct {
	grpc.ServerStream

	ctx context.Context //nolint:containedctx // required for mocking grpc.ServerStream
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

func TestUnaryServerInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		selfID      spec.KryptonID
		subAgentIDs []spec.KryptonID
		callerID    spec.KryptonID
		expCode     codes.Code
	}{
		// Rule 0: Trust domain mismatch
		{
			name:        "trust domain mismatch is denied",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			callerID:    spec.RootID("other-domain"),
			expCode:     codes.PermissionDenied,
		},

		// Rule 1: Root can call anyone
		{
			name:        "root can call agent-aws",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			callerID:    spec.RootID(testTrustDomain),
			expCode:     codes.OK,
		},
		{
			name:        "root can call agent-leaf",
			selfID:      spec.AgentID(testTrustDomain, "agent-leaf"),
			subAgentIDs: []spec.KryptonID{},
			callerID:    spec.RootID(testTrustDomain),
			expCode:     codes.OK,
		},
		{
			name:        "root can call root",
			selfID:      spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-aws")},
			callerID:    spec.RootID(testTrustDomain),
			expCode:     codes.OK,
		},

		// Rule 2: Anyone can call root
		{
			name:        "agent-aws can call root",
			selfID:      spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-aws")},
			callerID:    spec.AgentID(testTrustDomain, "agent-aws"),
			expCode:     codes.OK,
		},
		{
			name:        "agent-leaf can call root",
			selfID:      spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-aws")},
			callerID:    spec.AgentID(testTrustDomain, "agent-leaf"),
			expCode:     codes.OK,
		},
		{
			name:        "unknown agent can call root",
			selfID:      spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-aws")},
			callerID:    spec.AgentID(testTrustDomain, "unknown-agent"),
			expCode:     codes.OK,
		},

		// Rule 3: Sub-agent can call parent
		{
			name:        "sub-agent can call parent",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			callerID:    spec.AgentID(testTrustDomain, "agent-leaf"),
			expCode:     codes.OK,
		},

		// Rule 4: Denied cases
		{
			name:        "parent cannot call sub-agent",
			selfID:      spec.AgentID(testTrustDomain, "agent-leaf"),
			subAgentIDs: []spec.KryptonID{},
			callerID:    spec.AgentID(testTrustDomain, "agent-aws"),
			expCode:     codes.PermissionDenied,
		},
		{
			name:        "sibling cannot call sibling",
			selfID:      spec.AgentID(testTrustDomain, "agent-gcp"),
			subAgentIDs: []spec.KryptonID{},
			callerID:    spec.AgentID(testTrustDomain, "agent-aws"),
			expCode:     codes.PermissionDenied,
		},
		{
			name:        "unrelated agent cannot call agent",
			selfID:      spec.AgentID(testTrustDomain, "agent-gcp"),
			subAgentIDs: []spec.KryptonID{},
			callerID:    spec.AgentID(testTrustDomain, "agent-leaf"),
			expCode:     codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			az := authz.New(tt.selfID, tt.subAgentIDs)
			interceptor := az.UnaryServerInterceptor()
			ctx := contextWithKryptonID(t, tt.callerID)
			handler := func(ctx context.Context, req any) (any, error) {
				return "ok", nil
			}

			// when
			resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{}, handler)

			// then
			if tt.expCode != codes.OK {
				assert.Error(t, err)
				assert.Equal(t, tt.expCode, status.Code(err))
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, "ok", resp)
		})
	}
}

func TestUnaryServerInterceptor_MissingAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ctxFunc func() context.Context
		expCode codes.Code
	}{
		{
			name:    "no peer info",
			ctxFunc: context.Background,
			expCode: codes.Unauthenticated,
		},
		{
			name: "no TLS info",
			ctxFunc: func() context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{
					Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
				})
			},
			expCode: codes.Unauthenticated,
		},
		{
			name: "no client certificate",
			ctxFunc: func() context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{
					Addr:     &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
					AuthInfo: credentials.TLSInfo{},
				})
			},
			expCode: codes.Unauthenticated,
		},
		{
			name: "no krypton ID in certificate",
			ctxFunc: func() context.Context {
				// Certificate with non-krypton URI
				otherURI, _ := url.Parse("https://example.com")
				cert := &x509.Certificate{
					URIs: []*url.URL{otherURI},
				}
				tlsInfo := credentials.TLSInfo{
					State: tls.ConnectionState{
						PeerCertificates: []*x509.Certificate{cert},
					},
				}
				return peer.NewContext(context.Background(), &peer.Peer{
					Addr:     &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
					AuthInfo: tlsInfo,
				})
			},
			expCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			az := authz.New(spec.AgentID(testTrustDomain, "agent-aws"), []spec.KryptonID{})
			interceptor := az.UnaryServerInterceptor()

			// when
			_, err := interceptor(tt.ctxFunc(), nil, &grpc.UnaryServerInfo{}, nil)

			// then
			assert.Equal(t, tt.expCode, status.Code(err))
		})
	}
}

func TestStreamServerInterceptor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		selfID      spec.KryptonID
		subAgentIDs []spec.KryptonID
		callerID    spec.KryptonID
		expCode     codes.Code
	}{
		// Rule 0: Trust domain mismatch
		{
			name:        "trust domain mismatch is denied",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			callerID:    spec.RootID("other-domain"),
			expCode:     codes.PermissionDenied,
		},

		// Rule 1: Root can call anyone
		{
			name:        "root can call agent-aws",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			callerID:    spec.RootID(testTrustDomain),
			expCode:     codes.OK,
		},
		{
			name:        "root can call agent-leaf",
			selfID:      spec.AgentID(testTrustDomain, "agent-leaf"),
			subAgentIDs: []spec.KryptonID{},
			callerID:    spec.RootID(testTrustDomain),
			expCode:     codes.OK,
		},
		{
			name:        "root can call root",
			selfID:      spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-aws")},
			callerID:    spec.RootID(testTrustDomain),
			expCode:     codes.OK,
		},

		// Rule 2: Anyone can call root
		{
			name:        "agent-aws can call root",
			selfID:      spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-aws")},
			callerID:    spec.AgentID(testTrustDomain, "agent-aws"),
			expCode:     codes.OK,
		},
		{
			name:        "agent-leaf can call root",
			selfID:      spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-aws")},
			callerID:    spec.AgentID(testTrustDomain, "agent-leaf"),
			expCode:     codes.OK,
		},
		{
			name:        "unknown agent can call root",
			selfID:      spec.RootID(testTrustDomain),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-aws")},
			callerID:    spec.AgentID(testTrustDomain, "unknown-agent"),
			expCode:     codes.OK,
		},

		// Rule 3: Sub-agent can call parent
		{
			name:        "sub-agent can call parent",
			selfID:      spec.AgentID(testTrustDomain, "agent-aws"),
			subAgentIDs: []spec.KryptonID{spec.AgentID(testTrustDomain, "agent-leaf")},
			callerID:    spec.AgentID(testTrustDomain, "agent-leaf"),
			expCode:     codes.OK,
		},

		// Rule 4: Denied cases
		{
			name:        "parent cannot call sub-agent",
			selfID:      spec.AgentID(testTrustDomain, "agent-leaf"),
			subAgentIDs: []spec.KryptonID{},
			callerID:    spec.AgentID(testTrustDomain, "agent-aws"),
			expCode:     codes.PermissionDenied,
		},
		{
			name:        "sibling cannot call sibling",
			selfID:      spec.AgentID(testTrustDomain, "agent-gcp"),
			subAgentIDs: []spec.KryptonID{},
			callerID:    spec.AgentID(testTrustDomain, "agent-aws"),
			expCode:     codes.PermissionDenied,
		},
		{
			name:        "unrelated agent cannot call agent",
			selfID:      spec.AgentID(testTrustDomain, "agent-gcp"),
			subAgentIDs: []spec.KryptonID{},
			callerID:    spec.AgentID(testTrustDomain, "agent-leaf"),
			expCode:     codes.PermissionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			az := authz.New(tt.selfID, tt.subAgentIDs)
			interceptor := az.StreamServerInterceptor()
			stream := &mockServerStream{ctx: contextWithKryptonID(t, tt.callerID)}
			handler := func(srv any, ss grpc.ServerStream) error {
				return nil
			}

			// when
			err := interceptor(nil, stream, &grpc.StreamServerInfo{}, handler)

			// then
			if tt.expCode != codes.OK {
				assert.Error(t, err)
				assert.Equal(t, tt.expCode, status.Code(err))
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestStreamServerInterceptor_MissingAuth(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ctxFunc func() context.Context
		expCode codes.Code
	}{
		{
			name:    "no peer info",
			ctxFunc: context.Background,
			expCode: codes.Unauthenticated,
		},
		{
			name: "no TLS info",
			ctxFunc: func() context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{
					Addr: &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
				})
			},
			expCode: codes.Unauthenticated,
		},
		{
			name: "no client certificate",
			ctxFunc: func() context.Context {
				return peer.NewContext(context.Background(), &peer.Peer{
					Addr:     &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
					AuthInfo: credentials.TLSInfo{},
				})
			},
			expCode: codes.Unauthenticated,
		},
		{
			name: "no krypton ID in certificate",
			ctxFunc: func() context.Context {
				// Certificate with non-krypton URI
				otherURI, _ := url.Parse("https://example.com")
				cert := &x509.Certificate{
					URIs: []*url.URL{otherURI},
				}
				tlsInfo := credentials.TLSInfo{
					State: tls.ConnectionState{
						PeerCertificates: []*x509.Certificate{cert},
					},
				}
				return peer.NewContext(context.Background(), &peer.Peer{
					Addr:     &net.IPAddr{IP: net.ParseIP("127.0.0.1")},
					AuthInfo: tlsInfo,
				})
			},
			expCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// given
			az := authz.New(spec.AgentID(testTrustDomain, "agent-aws"), []spec.KryptonID{})
			interceptor := az.StreamServerInterceptor()
			stream := &mockServerStream{ctx: tt.ctxFunc()}

			// when
			err := interceptor(nil, stream, &grpc.StreamServerInfo{}, nil)

			// then
			assert.Equal(t, tt.expCode, status.Code(err))
		})
	}
}
