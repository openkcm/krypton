package kmip

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipserver"

	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/securemem"
)

// KeyIdentifier re-exports the parsed identifier for authorizer tests.
type KeyIdentifier = keyIdentifier

// Authorize exposes the authorizer for black-box tests.
func Authorize(ctx context.Context, uniqueIdentifier string) (KeyIdentifier, error) {
	return newAuthorizer().authorizeIdentifier(ctx, uniqueIdentifier)
}

// ListenAddress exposes (*Config).listenAddress for tests.
func ListenAddress(c *Config) string { return c.listenAddress() }

// SetPeerCertsFn swaps the package-level peer-cert resolver and returns a
// restore func for t.Cleanup.
func SetPeerCertsFn(fn func(context.Context) []*x509.Certificate) func() {
	prev := peerCertsFn
	peerCertsFn = fn
	return func() { peerCertsFn = prev }
}

// TestHandler drives the full request pipeline built by newHandler, auth
// middleware included.
type TestHandler struct{ exec kmipserver.RequestHandler }

func NewTestHandler(mgr *keyprocessor.Manager) *TestHandler {
	return &TestHandler{exec: newHandler(mgr)}
}

// Do runs a single-item batch and returns the resulting batch item.
func (t *TestHandler) Do(ctx context.Context, payload kmip.OperationPayload) *kmip.ResponseBatchItem {
	msg := kmip.NewRequestMessage(kmip.V1_4, payload)
	resp := t.exec.HandleRequest(ctx, &msg)
	if len(resp.BatchItem) != 1 {
		panic(fmt.Sprintf("expected 1 batch item, got %d", len(resp.BatchItem)))
	}
	return &resp.BatchItem[0]
}

// WithMemVault attaches a securemem.MemVault to ctx for tests exercising the
// handler's secure-copy path.
func WithMemVault(ctx context.Context, v *securemem.MemVault) context.Context {
	return withMemVault(ctx, v)
}

// PeekNextVaultName predicts the next vaultName result so tests can force an
// Import collision.
func PeekNextVaultName(uid string) string {
	return vaultEntryName(uid, vaultSeq.Load()+1)
}
