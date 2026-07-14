package kmip

import (
	"context"
	"crypto/x509"

	"github.com/ovh/kmip-go/payloads"

	"github.com/openkcm/krypton/internal/securemem"
)

var (
	ParseKeyIdentifier  = parseKeyIdentifier
	BuildTLSConfig      = buildTLSConfig
	ClientTenantFromCtx = clientTenantFromCtx
	AuthorizeTenant     = authorizeTenant
)

// ListenAddress exposes (*Config).listenAddress for tests.
func ListenAddress(c *Config) string { return c.listenAddress() }

// SetPeerCertsFn swaps the package-level peer-cert resolver and returns a
// restore func for t.Cleanup.
func SetPeerCertsFn(fn func(context.Context) []*x509.Certificate) func() {
	prev := peerCertsFn
	peerCertsFn = fn
	return func() { peerCertsFn = prev }
}

// TestHandler wraps the unexported handler so black-box tests can drive its
// operation methods.
type TestHandler struct{ h *handler }

func NewTestHandler(km KeyManager) *TestHandler {
	return &TestHandler{h: &handler{keyManager: km}}
}

func (t *TestHandler) Get(ctx context.Context, req *payloads.GetRequestPayload) (*payloads.GetResponsePayload, error) {
	return t.h.handleGet(ctx, req)
}

func (t *TestHandler) GetAttributes(ctx context.Context, req *payloads.GetAttributesRequestPayload) (*payloads.GetAttributesResponsePayload, error) {
	return t.h.handleGetAttributes(ctx, req)
}

// WithMemVault attaches a securemem.MemVault to ctx for tests exercising the
// handler's secure-copy path.
func WithMemVault(ctx context.Context, v *securemem.MemVault) context.Context {
	return withMemVault(ctx, v)
}
