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

// Authenticator validates that the client certificate's Common Name (CN) is in a configured allowlist.
type Authenticator struct {
	allowedCNs map[string]struct{}
}

// ErrNoAllowedCNs is returned when no valid CNs are provided to NewAuthenticator.
var ErrNoAllowedCNs = errors.New("no allowed CNs configured")

// NewAuthenticator creates an Authenticator from the given CN allowlist.
// Empty strings and whitespace-only entries are ignored. Returns ErrNoAllowedCNs
// if no valid CNs remain after filtering.
func NewAuthenticator(allowedCNs []string) (*Authenticator, error) {
	cns := make(map[string]struct{}, len(allowedCNs))
	for _, cn := range allowedCNs {
		cn = strings.TrimSpace(cn)
		if cn == "" {
			continue
		}
		cns[cn] = struct{}{}
	}
	if len(cns) == 0 {
		return nil, ErrNoAllowedCNs
	}
	return &Authenticator{allowedCNs: cns}, nil
}

// UnaryInterceptor is a gRPC unary server interceptor that checks the client
// certificate's CN against the allowlist. It returns PermissionDenied if the CN
// is not allowed, and Unauthenticated if TLS peer information is missing.
func (a *Authenticator) UnaryInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if len(a.allowedCNs) == 0 {
		return nil, status.Error(codes.PermissionDenied, "no allowed CNs configured")
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
	if _, allowed := a.allowedCNs[clientCert.Subject.CommonName]; !allowed {
		return nil, status.Error(codes.PermissionDenied, "unauthorized client")
	}

	return handler(ctx, req)
}
