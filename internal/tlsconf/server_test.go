package tlsconf_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/tlsconf"
)

func TestBuildTLSConfig(t *testing.T) {
	t.Parallel()
	pki := newTestPKI(t, "tenant-a")

	dir := t.TempDir()
	certPath, keyPath := pki.writeServerFiles(t, dir)
	caPath := filepath.Join(dir, "client-ca.pem")
	require.NoError(t, os.WriteFile(caPath, pki.caPEM, 0o600))

	cfg := tlsconf.Server{Cert: certPath, Key: keyPath, ClientCA: caPath}

	got, err := cfg.BuildTLSConfig()
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

		cfg := tlsconf.Server{
			Cert:     filepath.Join(dir, "nope.pem"),
			Key:      keyPath,
			ClientCA: filepath.Join(dir, "ca.pem"),
		}
		_, err := cfg.BuildTLSConfig()
		assert.Error(t, err)
	})

	t.Run("missing CA", func(t *testing.T) {
		t.Parallel()
		cfg := tlsconf.Server{
			Cert:     certPath,
			Key:      keyPath,
			ClientCA: filepath.Join(dir, "no-ca.pem"),
		}

		_, err := cfg.BuildTLSConfig()
		assert.Error(t, err)
	})

	t.Run("invalid CA PEM", func(t *testing.T) {
		t.Parallel()
		badCA := filepath.Join(dir, "bad-ca.pem")
		require.NoError(t, os.WriteFile(badCA, []byte("not a certificate"), 0o600))
		cfg := tlsconf.Server{
			Cert:     certPath,
			Key:      keyPath,
			ClientCA: badCA,
		}
		_, err := cfg.BuildTLSConfig()
		assert.ErrorIs(t, err, tlsconf.ErrCAInvalid)
	})
}

type testPKI struct {
	caPEM         []byte
	caCertFile    string
	serverCertPEM []byte
	serverKeyPEM  []byte
	clientCerts   map[string]testClientCert
}

type testClientCert struct {
	certPEM []byte
	keyPEM  []byte
}

// newTestPKI generates an in-memory CA, a server keypair (SAN=127.0.0.1), and
// one client keypair per clientCN. Files are written to a per-test temp dir
// and cleaned up automatically.
func newTestPKI(t *testing.T, clientCNs ...string) *testPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "gen CA key")
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err, "sign CA")
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err, "parse CA")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	serverCertPEM, serverKeyPEM := issueCert(t, caCert, caKey, pkix.Name{CommonName: "kmip-server"}, false, []net.IP{net.ParseIP("127.0.0.1")})

	pki := &testPKI{
		caPEM:         caPEM,
		serverCertPEM: serverCertPEM,
		serverKeyPEM:  serverKeyPEM,
		clientCerts:   make(map[string]testClientCert, len(clientCNs)),
	}
	for _, cn := range clientCNs {
		certPEM, keyPEM := issueCert(t, caCert, caKey, pkix.Name{CommonName: cn}, true, nil)
		pki.clientCerts[cn] = testClientCert{certPEM: certPEM, keyPEM: keyPEM}
	}

	dir := t.TempDir()
	pki.caCertFile = filepath.Join(dir, "ca.pem")
	writeFile(t, pki.caCertFile, caPEM)

	return pki
}

// writeServerFiles writes the server cert+key to the given temp dir and
// returns their paths.
func (p *testPKI) writeServerFiles(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(dir, "server.pem")
	keyPath = filepath.Join(dir, "server-key.pem")
	writeFile(t, certPath, p.serverCertPEM)
	writeFile(t, keyPath, p.serverKeyPEM)
	return certPath, keyPath
}

func issueCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, subject pkix.Name, client bool, ips []net.IP) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "gen key for %s", subject.CommonName)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "gen serial")
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  ips,
	}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	require.NoError(t, err, "sign cert for %s", subject.CommonName)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err, "marshal key for %s", subject.CommonName)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600), "write %s", path)
}
