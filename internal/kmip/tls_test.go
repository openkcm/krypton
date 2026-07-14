package kmip_test

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
)

func TestBuildTLSConfig(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "tenant-a")

	dir := t.TempDir()
	certPath, keyPath := pki.writeServerFiles(t, dir)
	caPath := filepath.Join(dir, "client-ca.pem")
	require.NoError(t, os.WriteFile(caPath, pki.caPEM, 0o600))

	cfg := kmip.TLSConfig{ServerCert: certPath, ServerKey: keyPath, ClientCA: caPath}
	got, err := kmip.BuildTLSConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, tls.RequireAndVerifyClientCert, got.ClientAuth)
	assert.GreaterOrEqual(t, got.MinVersion, uint16(tls.VersionTLS12))
	assert.NotNil(t, got.ClientCAs)
	assert.Len(t, got.Certificates, 1)
}

func TestBuildTLSConfigErrors(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t)
	dir := t.TempDir()
	certPath, keyPath := pki.writeServerFiles(t, dir)

	t.Run("missing server cert", func(t *testing.T) {
		t.Parallel()
		_, err := kmip.BuildTLSConfig(kmip.TLSConfig{
			ServerCert: filepath.Join(dir, "nope.pem"),
			ServerKey:  keyPath,
			ClientCA:   filepath.Join(dir, "ca.pem"),
		})
		assert.Error(t, err)
	})

	t.Run("missing CA", func(t *testing.T) {
		t.Parallel()
		_, err := kmip.BuildTLSConfig(kmip.TLSConfig{
			ServerCert: certPath,
			ServerKey:  keyPath,
			ClientCA:   filepath.Join(dir, "no-ca.pem"),
		})
		assert.Error(t, err)
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		t.Parallel()
		badCA := filepath.Join(dir, "bad-ca.pem")
		require.NoError(t, os.WriteFile(badCA, []byte("not a certificate"), 0o600))
		_, err := kmip.BuildTLSConfig(kmip.TLSConfig{
			ServerCert: certPath,
			ServerKey:  keyPath,
			ClientCA:   badCA,
		})
		assert.ErrorIs(t, err, kmip.ErrClientCAInvalid)
	})
}
