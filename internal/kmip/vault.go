package kmip

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/openkcm/krypton/internal/securemem"
)

// memVaultKey is the context key under which a per-connection securemem.MemVault
// is stored. The ConnectHook attaches a fresh vault; the TerminateHook drains it.
type memVaultKey struct{}

// withMemVault attaches v to ctx.
func withMemVault(ctx context.Context, v *securemem.MemVault) context.Context {
	return context.WithValue(ctx, memVaultKey{}, v)
}

// memVaultFromCtx returns the vault attached to ctx, or nil if none is present.
// Handlers that need to hold key material must treat a nil vault as fatal and
// refuse to serve rather than fall back to unlocked memory.
func memVaultFromCtx(ctx context.Context) *securemem.MemVault {
	v, _ := ctx.Value(memVaultKey{}).(*securemem.MemVault)
	return v
}

// vaultSeq makes vault entry names unique within a connection's vault, since
// MemVault.Reserve rejects duplicate names (e.g. repeated Get of the same key).
var vaultSeq atomic.Uint64

// vaultName builds a unique, non-secret vault entry name from the key
// identifier. The identifier is tenant:keyID — safe to log for bookkeeping.
func vaultName(uid string) string {
	return fmt.Sprintf("%s#%d", uid, vaultSeq.Add(1))
}
