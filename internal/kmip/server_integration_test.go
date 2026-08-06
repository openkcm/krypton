package kmip_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	ovhkmip "github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
)

func TestServerIntegration(t *testing.T) {
	pki := newTestPKI(t, "tenant-a", "tenant-b")
	serverCert, serverKey := pki.writeServerFiles(t, t.TempDir())

	tenantA := "tenant-a"
	keyID := "dek-int-001"
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i + 1)
	}

	env := newTestEnv(t, tenantA, keyID)
	env.seedSecret(t, material)

	cfg := kmip.Config{
		BindAddr: "127.0.0.1",
		Port:     freePort(t),
		TLS: kmip.TLSConfig{
			ServerCert: serverCert,
			ServerKey:  serverKey,
			ClientCA:   pki.caCertFile,
		},
	}
	srv, err := kmip.NewServer(cfg, env.mgr)
	require.NoError(t, err, "NewServer")

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	t.Cleanup(func() {
		_ = srv.Shutdown()
		if err := <-serveErr; err != nil && !errors.Is(err, kmipserver.ErrShutdown) {
			t.Errorf("Serve returned: %v", err)
		}
	})

	addr := srv.Addr().String()
	waitTLSReady(t, addr)

	uid := tenantA + ":" + keyID + ":1"

	t.Run("get with correct tenant", func(t *testing.T) {
		c := dialAs(t, addr, pki, tenantA)
		defer c.Close()

		resp, err := c.Get(uid).ExecContext(context.Background())
		require.NoError(t, err, "Get")
		assert.Equal(t, uid, resp.UniqueIdentifier)
		sk, ok := resp.Object.(*ovhkmip.SymmetricKey)
		require.True(t, ok, "Object type = %T", resp.Object)
		mat, err := sk.KeyMaterial()
		require.NoError(t, err, "KeyMaterial")
		assert.Equal(t, material, mat)
	})

	t.Run("get attributes returns metadata for the active key", func(t *testing.T) {
		c := dialAs(t, addr, pki, tenantA)
		defer c.Close()

		resp, err := c.GetAttributes(uid).ExecContext(context.Background())
		require.NoError(t, err, "GetAttributes")
		assert.Equal(t, uid, resp.UniqueIdentifier)
		got := indexAttrs(resp.Attribute)
		assert.Len(t, got, 4)
		assert.Equal(t, ovhkmip.StateActive, got[ovhkmip.AttributeNameState])
		assert.Equal(t, ovhkmip.CryptographicAlgorithmAES, got[ovhkmip.AttributeNameCryptographicAlgorithm])
		assert.Equal(t, int32(256), got[ovhkmip.AttributeNameCryptographicLength])
		assert.Equal(t, ovhkmip.ObjectTypeSymmetricKey, got[ovhkmip.AttributeNameObjectType])
	})

	t.Run("get attributes filters to requested names", func(t *testing.T) {
		c := dialAs(t, addr, pki, tenantA)
		defer c.Close()

		resp, err := c.GetAttributes(uid, ovhkmip.AttributeNameCryptographicLength).ExecContext(context.Background())
		require.NoError(t, err, "GetAttributes")
		got := indexAttrs(resp.Attribute)
		assert.Len(t, got, 1)
		assert.Equal(t, int32(256), got[ovhkmip.AttributeNameCryptographicLength])
	})

	t.Run("cross-tenant get rejected", func(t *testing.T) {
		c := dialAs(t, addr, pki, "tenant-b")
		defer c.Close()

		batch, err := c.Batch(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: uid})
		require.NoError(t, err, "Batch")
		require.Len(t, batch, 1)
		bi := batch[0]
		assert.NotEqual(t, ovhkmip.ResultStatusSuccess, bi.ResultStatus)
		assert.Equal(t, ovhkmip.ResultReasonPermissionDenied, bi.ResultReason)
	})

	t.Run("no client cert fails handshake", func(t *testing.T) {
		conn, err := tls.Dial("tcp", addr, &tls.Config{
			RootCAs:    poolFromPEM(t, pki.caPEM),
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		assert.Error(t, err, "expected read to fail after server rejects missing client cert")
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "reserve port")
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func dialAs(t *testing.T, addr string, pki *testPKI, cn string) *kmipclient.Client {
	t.Helper()
	cc, ok := pki.clientCerts[cn]
	require.True(t, ok, "no client cert for CN %q", cn)
	c, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem(pki.caPEM),
		kmipclient.WithClientCertPEM(cc.certPEM, cc.keyPEM),
		kmipclient.WithServerName("127.0.0.1"),
	)
	require.NoError(t, err, "Dial as %s", cn)
	return c
}

func waitTLSReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("KMIP server did not start listening on %s in time", addr)
}

func poolFromPEM(t *testing.T, pemBytes []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(pemBytes), "failed to parse PEM into cert pool")
	return pool
}
