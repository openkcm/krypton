package securemem

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/stats"
)

// RPCHandler is a gRPC [stats.Handler] that manages a per-RPC [MemVault].
// TagRPC creates a fresh vault and attaches it to the context; HandleRPC
// destroys the vault once the response has been serialized and sent.
type RPCHandler struct{}

type rpcVaultKey struct{}

var _ stats.Handler = &RPCHandler{}

// NewRPCHandler returns a new [RPCHandler].
func NewRPCHandler() *RPCHandler {
	return &RPCHandler{}
}

// TagRPC creates a new [MemVault] and stores it in the context.
func (h *RPCHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return vaultToContext(ctx, NewMemVault())
}

// HandleRPC destroys the vault after the response has been serialized and
// sent on the wire. Only acts on [stats.End]; all other events are ignored.
func (h *RPCHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	if _, ok := s.(*stats.End); !ok {
		return
	}

	vault, ok := VaultFromContext(ctx)
	if !ok {
		return
	}

	if err := vault.DestroyAll(); err != nil {
		slog.Error("failed to destroy vault", "error", err)
	}
}

// TagConn implements [stats.Handler]. No-op.
func (h *RPCHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

// HandleConn implements [stats.Handler]. No-op.
func (h *RPCHandler) HandleConn(context.Context, stats.ConnStats) {
}

// VaultFromContext retrieves the per-RPC [MemVault] stored by [RPCHandler].
func VaultFromContext(ctx context.Context) (*MemVault, bool) {
	res, ok := ctx.Value(rpcVaultKey{}).(*MemVault)
	return res, ok
}

// vaultToContext stores a [MemVault] in the context.
func vaultToContext(ctx context.Context, vault *MemVault) context.Context {
	return context.WithValue(ctx, rpcVaultKey{}, vault)
}
