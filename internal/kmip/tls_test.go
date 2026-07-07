package kmip

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildTLSConfig(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "tenant-a")

	dir := t.TempDir()
	certPath, keyPath := pki.writeServerFiles(t, dir)
	caPath := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caPath, pki.caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	cfg := TLSConfig{ServerCert: certPath, ServerKey: keyPath, ClientCA: caPath}
	got, err := buildTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildTLSConfig: %v", err)
	}
	if got.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want RequireAndVerifyClientCert", got.ClientAuth)
	}
	if got.MinVersion < tls.VersionTLS12 {
		t.Fatalf("MinVersion = %v, want >= TLS12", got.MinVersion)
	}
	if got.ClientCAs == nil {
		t.Fatal("ClientCAs is nil")
	}
	if len(got.Certificates) != 1 {
		t.Fatalf("Certificates: got %d, want 1", len(got.Certificates))
	}
}

func TestBuildTLSConfigErrors(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t)
	dir := t.TempDir()
	certPath, keyPath := pki.writeServerFiles(t, dir)

	t.Run("missing server cert", func(t *testing.T) {
		t.Parallel()
		_, err := buildTLSConfig(TLSConfig{
			ServerCert: filepath.Join(dir, "nope.pem"),
			ServerKey:  keyPath,
			ClientCA:   filepath.Join(dir, "ca.pem"),
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("missing CA", func(t *testing.T) {
		t.Parallel()
		_, err := buildTLSConfig(TLSConfig{
			ServerCert: certPath,
			ServerKey:  keyPath,
			ClientCA:   filepath.Join(dir, "no-ca.pem"),
		})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		t.Parallel()
		badCA := filepath.Join(dir, "bad-ca.pem")
		if err := os.WriteFile(badCA, []byte("not a certificate"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := buildTLSConfig(TLSConfig{
			ServerCert: certPath,
			ServerKey:  keyPath,
			ClientCA:   badCA,
		})
		if !errors.Is(err, ErrClientCAInvalid) {
			t.Fatalf("err = %v, want ErrClientCAInvalid", err)
		}
	})
}
