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

	cfg := tlsconf.Client{CertPath: certPath, KeyPath: keyPath, CAPath: caPath}

	got, err := cfg.BuildTLSConfig()
	require.NoError(t, err)
	assert.Equal(t, got.MinVersion, uint16(tls.VersionTLS12))
	assert.NotNil(t, got.RootCAs)
	assert.Len(t, got.Certificates, 1)
}

func TestClientValidate(t *testing.T) {
	// given
	tts := []struct {
		name    string
		cfg     tlsconf.Client
		wantErr error
	}{
		{
			name:    "valid config",
			cfg:     tlsconf.Client{CertPath: "cert.pem", KeyPath: "key.pem", CAPath: "ca.pem"},
			wantErr: nil,
		},
		{
			name:    "missing cert path",
			cfg:     tlsconf.Client{KeyPath: "key.pem", CAPath: "ca.pem"},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name:    "missing key path",
			cfg:     tlsconf.Client{CertPath: "cert.pem", CAPath: "ca.pem"},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
		{
			name:    "missing CA path",
			cfg:     tlsconf.Client{CertPath: "cert.pem", KeyPath: "key.pem"},
			wantErr: tlsconf.ErrInvalidTLSConfig,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			gotErr := tt.cfg.Validate()

			// then
			assert.Equal(t, tt.wantErr, gotErr)
		})
	}
}

func TestClientBuildTLSConfigErrors(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t)
	dir := t.TempDir()
	certPath, keyPath := pki.writeServerFiles(t, dir)

	t.Run("missing client cert", func(t *testing.T) {
		t.Parallel()

		cfg := tlsconf.Client{
			CertPath: filepath.Join(dir, "nope.pem"),
			KeyPath:  keyPath,
			CAPath:   filepath.Join(dir, "ca.pem"),
		}
		_, err := cfg.BuildTLSConfig()
		assert.Error(t, err)
	})

	t.Run("missing CA", func(t *testing.T) {
		t.Parallel()
		cfg := tlsconf.Client{
			CertPath: certPath,
			KeyPath:  keyPath,
			CAPath:   filepath.Join(dir, "no-ca.pem"),
		}

		_, err := cfg.BuildTLSConfig()
		assert.Error(t, err)
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		t.Parallel()
		badCA := filepath.Join(dir, "bad-ca.pem")
		require.NoError(t, os.WriteFile(badCA, []byte("not a certificate"), 0o600))
		cfg := tlsconf.Client{
			CertPath: certPath,
			KeyPath:  keyPath,
			CAPath:   badCA,
		}
		_, err := cfg.BuildTLSConfig()
		assert.ErrorIs(t, err, tlsconf.ErrCAInvalid)
	})
}
