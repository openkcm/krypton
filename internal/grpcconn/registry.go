// Package grpcconn provides a name-keyed registry of gRPC client connections.
package grpcconn

import (
	"errors"
	"fmt"
	"sync"

	"google.golang.org/grpc"

	"github.com/openkcm/krypton/internal/config"
)

var (
	// ErrDuplicateName is returned when two ConnectionConfigs share a Name.
	ErrDuplicateName = errors.New("grpcconn: duplicate connection name")
	// ErrUnsupportedAddressType is returned when an Address.Type is not AddressTypeGRPC.
	ErrUnsupportedAddressType = errors.New("grpcconn: unsupported address type")
)

// Registry holds gRPC client connections keyed by connection name.
type Registry struct {
	mu    sync.RWMutex
	conns map[string]*grpc.ClientConn
}

// NewRegistry dials one *grpc.ClientConn per config entry. On any failure it
// closes all previously-dialed connections and returns the error.
func NewRegistry(cfgs []config.ConnectionConfig, opts ...grpc.DialOption) (*Registry, error) {
	r := &Registry{
		conns: make(map[string]*grpc.ClientConn, len(cfgs)),
	}

	for _, cfg := range cfgs {
		if _, ok := r.conns[cfg.Name]; ok {
			_ = r.Close()
			return nil, fmt.Errorf("%w: %q", ErrDuplicateName, cfg.Name)
		}
		if cfg.Address.Type != config.AddressTypeGRPC {
			_ = r.Close()
			return nil, fmt.Errorf("%w: %q has type %q, want %q",
				ErrUnsupportedAddressType, cfg.Name, cfg.Address.Type, config.AddressTypeGRPC)
		}

		conn, err := grpc.NewClient(cfg.Address.URL, opts...)
		if err != nil {
			_ = r.Close()
			return nil, fmt.Errorf("grpcconn: dial %q (%s): %w", cfg.Name, cfg.Address.URL, err)
		}
		r.conns[cfg.Name] = conn
	}

	return r, nil
}

// Get returns the connection registered under name. The bool reports whether
// a connection exists.
func (r *Registry) Get(name string) (*grpc.ClientConn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	conn, ok := r.conns[name]
	return conn, ok
}

// Close closes every connection and empties the Registry. Safe to call more than once.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.conns) == 0 {
		r.conns = nil
		return nil
	}

	errs := make([]error, 0, len(r.conns))
	for name, conn := range r.conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("grpcconn: close %q: %w", name, err))
		}
	}
	r.conns = nil
	return errors.Join(errs...)
}
