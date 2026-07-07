package kmip

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ovh/kmip-go"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/kmipserver"
	"github.com/ovh/kmip-go/payloads"

	"github.com/openkcm/krypton/pkg/model"
)

// TestServerIntegration exercises the KMIP server end-to-end over a real
// mTLS TCP listener with kmipclient. It verifies:
//   - happy-path Get returns the seeded DEK material
//   - happy-path GetAttributes returns the expected metadata
//   - cross-tenant Get is rejected with PermissionDenied
//   - a client without a certificate fails the TLS handshake
func TestServerIntegration(t *testing.T) {
	pki := newTestPKI(t, "tenant-a", "tenant-b")
	serverCert, serverKey := pki.writeServerFiles(t, t.TempDir())

	tenantA := "tenant-a"
	keyID := "dek-int-001"
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i + 1)
	}

	km, err := NewMemKeyManager(SeedDEK{
		TenantID:   tenantA,
		KeyID:      keyID,
		Material:   material,
		Algorithm:  AlgorithmAES,
		LengthBits: 256,
		State:      model.KeyLifeCycleActive,
	})
	if err != nil {
		t.Fatalf("NewMemKeyManager: %v", err)
	}
	t.Cleanup(func() { _ = km.(*memKeyManager).Close() })

	cfg := Config{
		BindAddr: "127.0.0.1",
		Port:     freePort(t),
		TLS: TLSConfig{
			ServerCert: serverCert,
			ServerKey:  serverKey,
			ClientCA:   pki.caCertFile,
		},
	}
	srv, err := NewServer(cfg, km)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

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

	uid := tenantA + ":" + keyID

	t.Run("get with correct tenant", func(t *testing.T) {
		c := dialAs(t, addr, pki, tenantA)
		defer c.Close()

		resp, err := c.Get(uid).ExecContext(context.Background())
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if resp.UniqueIdentifier != uid {
			t.Fatalf("UniqueIdentifier = %q", resp.UniqueIdentifier)
		}
		sk, ok := resp.Object.(*kmip.SymmetricKey)
		if !ok {
			t.Fatalf("Object type = %T", resp.Object)
		}
		mat, err := sk.KeyMaterial()
		if err != nil {
			t.Fatalf("KeyMaterial: %v", err)
		}
		if string(mat) != string(material) {
			t.Fatalf("material mismatch")
		}
	})

	t.Run("get attributes with correct tenant", func(t *testing.T) {
		c := dialAs(t, addr, pki, tenantA)
		defer c.Close()

		resp, err := c.GetAttributes(uid).ExecContext(context.Background())
		if err != nil {
			t.Fatalf("GetAttributes: %v", err)
		}
		got := indexAttrs(resp.Attribute)
		if got[kmip.AttributeNameState] != kmip.StateActive {
			t.Fatalf("State = %v", got[kmip.AttributeNameState])
		}
		if got[kmip.AttributeNameCryptographicAlgorithm] != kmip.CryptographicAlgorithmAES {
			t.Fatalf("Algorithm = %v", got[kmip.AttributeNameCryptographicAlgorithm])
		}
		if got[kmip.AttributeNameCryptographicLength] != int32(256) {
			t.Fatalf("Length = %v", got[kmip.AttributeNameCryptographicLength])
		}
		if got[kmip.AttributeNameObjectType] != kmip.ObjectTypeSymmetricKey {
			t.Fatalf("ObjectType = %v", got[kmip.AttributeNameObjectType])
		}
	})

	t.Run("cross-tenant get rejected", func(t *testing.T) {
		c := dialAs(t, addr, pki, "tenant-b")
		defer c.Close()

		batch, err := c.Batch(context.Background(), &payloads.GetRequestPayload{UniqueIdentifier: uid})
		if err != nil {
			t.Fatalf("Batch: %v", err)
		}
		if len(batch) != 1 {
			t.Fatalf("batch len = %d, want 1", len(batch))
		}
		bi := batch[0]
		if bi.ResultStatus == kmip.ResultStatusSuccess {
			t.Fatalf("expected failure, got success")
		}
		if bi.ResultReason != kmip.ResultReasonPermissionDenied {
			t.Fatalf("ResultReason = %v, want PermissionDenied", bi.ResultReason)
		}
	})

	t.Run("no client cert fails handshake", func(t *testing.T) {
		c, err := kmipclient.Dial(addr,
			kmipclient.WithRootCAPem(pki.caPEM),
			kmipclient.WithServerName("127.0.0.1"),
		)
		if err == nil {
			_ = c.Close()
			t.Fatal("expected Dial to fail without client cert")
		}
	})
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func dialAs(t *testing.T, addr string, pki *testPKI, cn string) *kmipclient.Client {
	t.Helper()
	cc, ok := pki.clientCerts[cn]
	if !ok {
		t.Fatalf("no client cert for CN %q", cn)
	}
	c, err := kmipclient.Dial(addr,
		kmipclient.WithRootCAPem(pki.caPEM),
		kmipclient.WithClientCertPEM(cc.certPEM, cc.keyPEM),
		kmipclient.WithServerName("127.0.0.1"),
	)
	if err != nil {
		t.Fatalf("Dial as %s: %v", cn, err)
	}
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
