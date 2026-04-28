package authz

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/spec"
)

// UnaryServerInterceptor returns a gRPC unary server interceptor that performs
// authorization based on the client's certificate URI SAN (kryptonid://).
func (a *AuthZ) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := a.authorizeGRPCConnection(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor returns a gRPC stream server interceptor that performs
// authorization based on the client's certificate URI SAN (kryptonid://).
func (a *AuthZ) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := a.authorizeGRPCConnection(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// authorizeGRPCConnection performs the authorization check for gRPC connections,
// extracting the caller identity from the context's peer TLS info.
func (a *AuthZ) authorizeGRPCConnection(ctx context.Context) error {
	callerID, err := extractCallerID(ctx)
	if err != nil {
		return err
	}

	authCtx := Context{
		CallerID: callerID,
		TargetID: a.selfID,
	}

	if err := a.authorize(authCtx); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}

	return nil
}

// extractCallerID extracts the KryptonID from the client's TLS certificate URI SAN.
func extractCallerID(ctx context.Context) (spec.KryptonID, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return spec.KryptonID{}, status.Error(codes.Unauthenticated, "no peer info")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return spec.KryptonID{}, status.Error(codes.Unauthenticated, "no TLS info")
	}

	if len(tlsInfo.State.PeerCertificates) == 0 {
		return spec.KryptonID{}, status.Error(codes.Unauthenticated, "no client certificate")
	}

	id, err := spec.KryptonIDFromCertificate(tlsInfo.State.PeerCertificates[0])
	if err != nil {
		return spec.KryptonID{}, status.Error(codes.Unauthenticated, err.Error())
	}

	return id, nil
}
