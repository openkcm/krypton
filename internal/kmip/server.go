package kmip

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/ovh/kmip-go/kmipserver"

	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/securemem"
)

// Server is a thin wrapper around kmipserver.Server that owns the TLS
// listener and per-connection secure-memory vaults.
type Server struct {
	inner    *kmipserver.Server
	listener net.Listener
}

// NewServer opens an mTLS listener and serves KMIP backed by the manager.
// Each connection gets a fresh securemem.MemVault (ConnectHook) that the
// TerminateHook destroys, so served key material is zeroed on disconnect.
func NewServer(cfg Config, mgr *keyprocessor.Manager) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("kmip: invalid config: %w", err)
	}
	tlsCfg, err := buildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("kmip: build tls config: %w", err)
	}

	ln, err := tls.Listen("tcp", cfg.listenAddress(), tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("kmip: listen %s: %w", cfg.listenAddress(), err)
	}

	inner := kmipserver.NewServer(ln, newHandler(mgr)).
		WithConnectHook(func(ctx context.Context) (context.Context, error) {
			return withMemVault(ctx, securemem.NewMemVault()), nil
		}).
		WithTerminateHook(func(ctx context.Context) {
			if v := memVaultFromCtx(ctx); v != nil {
				_ = v.DestroyAll()
			}
		})

	return &Server{inner: inner, listener: ln}, nil
}

// Addr returns the listener's local address. Useful in tests that bind to
// port 0.
func (s *Server) Addr() net.Addr { return s.listener.Addr() }

// Serve blocks until Shutdown is called or an accept error occurs.
func (s *Server) Serve() error { return s.inner.Serve() }

// Shutdown closes the listener and waits for in-flight requests to
// complete (bounded by kmipserver's internal 3-second grace period).
func (s *Server) Shutdown() error { return s.inner.Shutdown() }

// memVaultKey is the context key for the per-connection securemem.MemVault.
type memVaultKey struct{}

func withMemVault(ctx context.Context, v *securemem.MemVault) context.Context {
	return context.WithValue(ctx, memVaultKey{}, v)
}

// memVaultFromCtx returns the per-connection vault, or nil; handlers must
// fail closed on nil rather than fall back to unlocked memory.
func memVaultFromCtx(ctx context.Context) *securemem.MemVault {
	v, _ := ctx.Value(memVaultKey{}).(*securemem.MemVault)
	return v
}

// vaultSeq disambiguates vault entry names, since MemVault.Import rejects
// duplicates (e.g. repeated Get of the same key).
var vaultSeq atomic.Uint64

// vaultName builds a unique, non-secret vault entry name for the identifier.
func vaultName(uid string) string {
	return vaultEntryName(uid, vaultSeq.Add(1))
}

func vaultEntryName(uid string, seq uint64) string {
	return fmt.Sprintf("%s#%d", uid, seq)
}
