package kmip

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/ovh/kmip-go/kmipserver"
)

// Server is a thin wrapper around kmipserver.Server that owns the TLS
// listener and per-connection wipe registries.
type Server struct {
	inner    *kmipserver.Server
	listener net.Listener
}

// NewServer validates the config, opens an mTLS listener, and wires the
// KMIP handler onto a kmipserver.Server. It attaches a fresh wipeRegistry
// to each connection via ConnectHook and drains it via TerminateHook so
// key material buffers referenced by response payloads are zeroed after
// the connection ends.
func NewServer(cfg Config, km KeyManager) (*Server, error) {
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

	inner := kmipserver.NewServer(ln, newHandler(km)).
		WithConnectHook(func(ctx context.Context) (context.Context, error) {
			return withWipeRegistry(ctx, newWipeRegistry()), nil
		}).
		WithTerminateHook(func(ctx context.Context) {
			if reg := wipeRegistryFromCtx(ctx); reg != nil {
				reg.wipeAll()
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
