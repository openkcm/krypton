package kmip_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
)

// withPeerCerts swaps the package-level peer-cert resolver for the duration of
// a test and restores the previous value on cleanup.
func withPeerCerts(t *testing.T, certs []*x509.Certificate) {
	t.Helper()
	restore := kmip.SetPeerCertsFn(func(context.Context) []*x509.Certificate { return certs })
	t.Cleanup(restore)
}

func certWithCN(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

func TestClientTenantFromCtx(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a")})
		got, err := kmip.ClientTenantFromCtx(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", got)
	})

	t.Run("no cert", func(t *testing.T) {
		withPeerCerts(t, nil)
		_, err := kmip.ClientTenantFromCtx(context.Background())
		assert.ErrorIs(t, err, kmip.ErrNoClientCert)
	})

	t.Run("empty CN", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("")})
		_, err := kmip.ClientTenantFromCtx(context.Background())
		assert.ErrorIs(t, err, kmip.ErrNoClientCert)
	})

	t.Run("uses first cert", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a"), certWithCN("tenant-b")})
		got, err := kmip.ClientTenantFromCtx(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", got)
	})
}

func TestAuthorizeTenant(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a")})
		assert.NoError(t, kmip.AuthorizeTenant(context.Background(), "tenant-a"))
	})

	t.Run("mismatch", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a")})
		err := kmip.AuthorizeTenant(context.Background(), "tenant-b")
		assert.ErrorIs(t, err, kmip.ErrTenantMismatch)
	})

	t.Run("no cert", func(t *testing.T) {
		withPeerCerts(t, nil)
		err := kmip.AuthorizeTenant(context.Background(), "tenant-a")
		assert.ErrorIs(t, err, kmip.ErrNoClientCert)
	})
}
