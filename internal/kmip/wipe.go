package kmip

import (
	"context"
	"sync"

	"github.com/openkcm/krypton/internal/securemem"
)

// wipeRegistry holds byte slices that must be zeroed when a KMIP connection
// terminates. Each connection has its own registry stored on the connection
// context; the ConnectHook attaches it and the TerminateHook drains it.
type wipeRegistry struct {
	mu      sync.Mutex
	buffers [][]byte
}

func newWipeRegistry() *wipeRegistry { return &wipeRegistry{} }

// register appends the buffer for later wiping. The buffer must not be
// modified or reused elsewhere after this call.
func (r *wipeRegistry) register(buf []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buffers = append(r.buffers, buf)
}

// wipeAll zeros every registered buffer and clears the registry.
func (r *wipeRegistry) wipeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, buf := range r.buffers {
		securemem.Zero(buf)
	}
	r.buffers = nil
}

type wipeRegistryKey struct{}

// withWipeRegistry attaches a fresh registry to ctx.
func withWipeRegistry(ctx context.Context, r *wipeRegistry) context.Context {
	return context.WithValue(ctx, wipeRegistryKey{}, r)
}

// wipeRegistryFromCtx returns the registry attached to ctx, or nil if none
// is present. Handlers should treat a nil registry as best-effort — the
// caller is responsible for wiping their own copies.
func wipeRegistryFromCtx(ctx context.Context) *wipeRegistry {
	r, _ := ctx.Value(wipeRegistryKey{}).(*wipeRegistry)
	return r
}
