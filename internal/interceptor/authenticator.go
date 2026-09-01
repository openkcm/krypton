package interceptor

import (
	"context"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Authenticator validates that the client certificate's URI SAN is in a configured allowlist.
type Authenticator struct {
	allowedURIs map[string]struct{}
}

// ErrNoAllowedURIs is returned when no valid URIs are provided to NewAuthenticator.
var ErrNoAllowedURIs = errors.New("no allowed URIs configured")

// NewAuthenticator creates an Authenticator from the given URI allowlist.
// Empty strings and whitespace-only entries are ignored. Returns ErrNoAllowedURIs
// if no valid URIs remain after filtering.
func NewAuthenticator(allowedURIs []string) (*Authenticator, error) {
	uris := make(map[string]struct{}, len(allowedURIs))
	for _, u := range allowedURIs {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		uris[u] = struct{}{}
	}
	if len(uris) == 0 {
		return nil, ErrNoAllowedURIs
	}
	return &Authenticator{allowedURIs: uris}, nil
}

// UnaryInterceptor is a gRPC unary server interceptor that checks the client
// certificate's URI against the allowlist. It returns PermissionDenied if the URI
// is not allowed, and Unauthenticated if TLS peer information is missing.
func (a *Authenticator) UnaryInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if len(a.allowedURIs) == 0 {
		return nil, status.Error(codes.PermissionDenied, "no allowed URIs configured")
	}

	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no peer info")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "no TLS info")
	}

	if len(tlsInfo.State.VerifiedChains) == 0 {
		return nil, status.Error(codes.Unauthenticated, "no verified chains")
	}

	clientCert := tlsInfo.State.VerifiedChains[0][0]
	uris := clientCert.URIs
	// https://spiffe.io/docs/latest/spiffe-specs/x509-svid/#2-spiffe-id
	if len(uris) != 1 {
		return nil, status.Error(codes.Unauthenticated, "invalid number of URIs in client certificate")
	}
	if _, allowed := a.allowedURIs[uris[0].String()]; !allowed {
		return nil, status.Error(codes.PermissionDenied, "unauthorized client")
	}

	return handler(ctx, req)
}
