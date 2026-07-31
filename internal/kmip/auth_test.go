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

func TestAuthorize(t *testing.T) {
	t.Run("parses tenant, key, and version from the identifier", func(t *testing.T) {
		tests := []struct {
			in          string
			wantTenant  string
			wantKey     string
			wantVersion int
		}{
			{"tenant-a:dek-1:1", "tenant-a", "dek-1", 1},
			{"acme-corp:dek-mongodb-001:42", "acme-corp", "dek-mongodb-001", 42},
		}
		for _, tt := range tests {
			t.Run(tt.in, func(t *testing.T) {
				withPeerCerts(t, []*x509.Certificate{certWithCN(tt.wantTenant)})
				got, err := kmip.Authorize(context.Background(), tt.in)
				require.NoError(t, err)
				assert.Equal(t, tt.wantTenant, got.TenantID)
				assert.Equal(t, tt.wantKey, got.KeyID)
				assert.Equal(t, tt.wantVersion, got.Version)
			})
		}
	})

	t.Run("rejects malformed identifiers", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a")})
		for _, in := range []string{
			"invalid-no-colon",
			"tenant-a:missing-version",
			"tenant:key:with:colons",
			":key:1",
			"tenant::1",
			"tenant:key:",
			"",
			"::",
			"tenant-a:dek-1:not-valid-int",
		} {
			t.Run(in, func(t *testing.T) {
				_, err := kmip.Authorize(context.Background(), in)
				assert.ErrorIs(t, err, kmip.ErrInvalidKeyIdentifier)
			})
		}
	})

	t.Run("matching CN is authorized, first cert wins", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a"), certWithCN("tenant-b")})
		got, err := kmip.Authorize(context.Background(), "tenant-a:dek-1:1")
		require.NoError(t, err)
		assert.Equal(t, "tenant-a", got.TenantID)

		_, err = kmip.Authorize(context.Background(), "tenant-b:dek-1:1")
		assert.ErrorIs(t, err, kmip.ErrTenantMismatch)
	})

	t.Run("no cert -> ErrNoClientCert", func(t *testing.T) {
		withPeerCerts(t, nil)
		_, err := kmip.Authorize(context.Background(), "tenant-a:dek-1:1")
		assert.ErrorIs(t, err, kmip.ErrNoClientCert)
	})

	t.Run("empty CN -> ErrNoClientCert", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("")})
		_, err := kmip.Authorize(context.Background(), "tenant-a:dek-1:1")
		assert.ErrorIs(t, err, kmip.ErrNoClientCert)
	})
}
