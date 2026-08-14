package tlsconf_test

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/tlsconf"
)

func TestClientBuildTLSConfig(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "tenant-a")

	dir := t.TempDir()
	certPath, keyPath := pki.writeServerFiles(t, dir)
	caPath := filepath.Join(dir, "client-ca.pem")
	require.NoError(t, os.WriteFile(caPath, pki.caPEM, 0o600))

	cfg := tlsconf.Client{Cert: certPath, Key: keyPath, ServerCA: caPath}

	got, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, got.MinVersion, uint16(tls.VersionTLS12))
	assert.NotNil(t, got.RootCAs)
	assert.Len(t, got.Certificates, 1)
}

func TestClientBuildTLSConfigErrors(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t)
	dir := t.TempDir()
	certPath, keyPath := pki.writeServerFiles(t, dir)

	t.Run("missing client cert", func(t *testing.T) {
		t.Parallel()

		cfg := tlsconf.Client{
			Cert:     filepath.Join(dir, "nope.pem"),
			Key:      keyPath,
			ServerCA: filepath.Join(dir, "ca.pem"),
		}
		_, err := cfg.BuildTLSConfig()
		assert.Error(t, err)
	})

	t.Run("missing CA", func(t *testing.T) {
		t.Parallel()
		cfg := tlsconf.Client{
			Cert:     certPath,
			Key:      keyPath,
			ServerCA: filepath.Join(dir, "no-ca.pem"),
		}

		_, err := cfg.BuildTLSConfig()
		assert.Error(t, err)
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		t.Parallel()
		badCA := filepath.Join(dir, "bad-ca.pem")
		require.NoError(t, os.WriteFile(badCA, []byte("not a certificate"), 0o600))
		cfg := tlsconf.Client{
			Cert:     certPath,
			Key:      keyPath,
			ServerCA: badCA,
		}
		_, err := cfg.BuildTLSConfig()
		assert.ErrorIs(t, err, tlsconf.ErrCAInvalid)
	})
}
