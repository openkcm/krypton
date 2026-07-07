package kmip

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
)

// withPeerCerts swaps the package-level peerCertsFn for the duration of a
// test and restores the previous value on cleanup.
func withPeerCerts(t *testing.T, certs []*x509.Certificate) {
	t.Helper()
	prev := peerCertsFn
	peerCertsFn = func(context.Context) []*x509.Certificate { return certs }
	t.Cleanup(func() { peerCertsFn = prev })
}

func certWithCN(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}}
}

func TestClientTenantFromCtx(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a")})
		got, err := clientTenantFromCtx(context.Background())
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if got != "tenant-a" {
			t.Fatalf("got %q, want tenant-a", got)
		}
	})

	t.Run("no cert", func(t *testing.T) {
		withPeerCerts(t, nil)
		_, err := clientTenantFromCtx(context.Background())
		if !errors.Is(err, ErrNoClientCert) {
			t.Fatalf("err = %v, want ErrNoClientCert", err)
		}
	})

	t.Run("empty CN", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("")})
		_, err := clientTenantFromCtx(context.Background())
		if !errors.Is(err, ErrNoClientCert) {
			t.Fatalf("err = %v, want ErrNoClientCert", err)
		}
	})

	t.Run("uses first cert", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a"), certWithCN("tenant-b")})
		got, err := clientTenantFromCtx(context.Background())
		if err != nil || got != "tenant-a" {
			t.Fatalf("got (%q, %v), want tenant-a", got, err)
		}
	})
}

func TestAuthorizeTenant(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a")})
		if err := authorizeTenant(context.Background(), "tenant-a"); err != nil {
			t.Fatalf("err: %v", err)
		}
	})

	t.Run("mismatch", func(t *testing.T) {
		withPeerCerts(t, []*x509.Certificate{certWithCN("tenant-a")})
		err := authorizeTenant(context.Background(), "tenant-b")
		if !errors.Is(err, ErrTenantMismatch) {
			t.Fatalf("err = %v, want ErrTenantMismatch", err)
		}
	})

	t.Run("no cert", func(t *testing.T) {
		withPeerCerts(t, nil)
		err := authorizeTenant(context.Background(), "tenant-a")
		if !errors.Is(err, ErrNoClientCert) {
			t.Fatalf("err = %v, want ErrNoClientCert", err)
		}
	})
}
