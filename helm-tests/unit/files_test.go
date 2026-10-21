//go:build helmtests

package unit_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/status"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/interceptor"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
)

// The file tests write the TLS files that the configuration examples of values.yaml name, in
// the formats that values.yaml documents (extraVolumes), and use them the way the root node
// does: the gRPC server with mutual TLS and the identity check of config.auth, and the TLS
// server of the KMIP server.

// The DNS name of the root node's Service in the tests.
const serviceDNSName = "krypton-root.services.svc"

// fileRoot maps paths in the container to a temporary directory.
type fileRoot string

func newFileRoot(t *testing.T) fileRoot {
	t.Helper()
	return fileRoot(t.TempDir())
}

func (r fileRoot) path(containerPath string) string {
	return filepath.Join(string(r), containerPath)
}

func (r fileRoot) write(t *testing.T, containerPath string, content []byte) {
	t.Helper()

	path := r.path(containerPath)

	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err == nil {
		err = os.WriteFile(path, content, 0o600)
	}

	if err != nil {
		t.Fatal(err)
	}
}

// identityURI returns the identity URI of the node in config.auth.identity.
func identityURI(t *testing.T, cfg *config.RootConfig, name string) string {
	t.Helper()

	for _, id := range cfg.Auth.IdentityConfigs {
		if id.Name == name {
			return string(id.URI)
		}
	}

	t.Fatalf("config.auth.identity has no entry %q", name)

	return ""
}

// clientCertificate returns the client certificate of a node with the identity URIs, in the
// key format.
func clientCertificate(t *testing.T, pki *testPKI, format keyFormat, name string, uris ...string) tls.Certificate {
	t.Helper()

	certFile, keyFile, _ := pki.files(t, format, name, uris)

	return must(tls.X509KeyPair(certFile, keyFile))(t)
}

// TestFilesAuth runs the gRPC server with the mutual TLS of the config.auth example, as
// cmd/root/main.go does, and calls it with client certificates of the agent of the example
// and of unknown clients.
func TestFilesAuth(t *testing.T) {
	cfg := loadValues(t, "-f", writeValues(t, exampleValues(t)))
	mtls := must(config.GetAuthConfig(cfg.Auth.Config))(t)
	agent := cfg.Topology.Segments[0].Name

	for _, format := range keyFormats {
		t.Run(format.name, func(t *testing.T) {
			pki := newTestPKI(t)
			root := newFileRoot(t)

			certFile, keyFile, caFile := pki.files(t, format, cfg.Name,
				[]string{identityURI(t, cfg, cfg.Name)}, serviceDNSName)
			for _, tlsFiles := range []config.TLSServer{mtls.Server, config.TLSServer(mtls.Client)} {
				root.write(t, tlsFiles.CertPath, certFile)
				root.write(t, tlsFiles.KeyPath, keyFile)
				root.write(t, tlsFiles.CAPath, caFile)
			}

			server := config.TLSServer{
				CertPath: root.path(mtls.Server.CertPath),
				KeyPath:  root.path(mtls.Server.KeyPath),
				CAPath:   root.path(mtls.Server.CAPath),
			}
			client := config.TLSClient{
				CertPath: root.path(mtls.Client.CertPath),
				KeyPath:  root.path(mtls.Client.KeyPath),
				CAPath:   root.path(mtls.Client.CAPath),
			}

			if _, err := client.BuildTLSConfig(); err != nil {
				t.Errorf("auth.config.client: %v", err)
			}

			address := grpcServer(t, must(server.BuildTLSConfig())(t), cfg.Auth.IdentityConfigs.URIs())

			call := func(t *testing.T, certs ...tls.Certificate) error {
				t.Helper()

				return checkHealth(t, address, &tls.Config{
					Certificates: certs,
					RootCAs:      pki.rootPool(),
					ServerName:   serviceDNSName,
					MinVersion:   tls.VersionTLS13,
				})
			}

			t.Run("agent of the topology", func(t *testing.T) {
				err := call(t, clientCertificate(t, pki, format, agent, identityURI(t, cfg, agent)))
				if err != nil {
					t.Errorf("the agent cannot call the root node: %v", err)
				}
			})

			t.Run("unknown identity", func(t *testing.T) {
				err := call(t, clientCertificate(t, pki, format, "other", "kryptonid://example.org/node/other"))
				if status.Code(err) != codes.PermissionDenied {
					t.Errorf("want PermissionDenied, got %v", err)
				}
			})

			t.Run("certificate of a CA that ca.crt does not contain", func(t *testing.T) {
				key := format.newKey(t)
				cert := newRootCA(t, "Unrelated CA").issue(t, key, agent, []string{identityURI(t, cfg, agent)})
				certificate := tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}

				if err := call(t, certificate); err == nil {
					t.Error("a client certificate of another CA is accepted")
				}
			})

			t.Run("no client certificate", func(t *testing.T) {
				if err := call(t); err == nil {
					t.Error("a client without certificate is accepted")
				}
			})
		})
	}
}

// grpcServer starts a gRPC server with the TLS configuration and the identity check of the
// root node, with the gRPC health service, and returns its address.
func grpcServer(t *testing.T, tlsConfig *tls.Config, identities []string) string {
	t.Helper()

	authn := must(interceptor.NewAuthenticator(identities))(t)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)), grpc.UnaryInterceptor(authn.UnaryInterceptor))
	healthpb.RegisterHealthServer(server, health.NewServer())

	listener := must((&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0"))(t)

	go func() { _ = server.Serve(listener) }()

	t.Cleanup(server.Stop)

	return listener.Addr().String()
}

// checkHealth calls the gRPC health service at the address with the TLS configuration.
func checkHealth(t *testing.T, address string, tlsConfig *tls.Config) error {
	t.Helper()

	conn := must(grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))))(t)
	defer conn.Close()

	_, err := healthpb.NewHealthClient(conn).Check(t.Context(), &healthpb.HealthCheckRequest{})

	return err
}

// TestFilesKMIP builds the TLS server of the config.kmip example and connects to it with and
// without client certificate.
func TestFilesKMIP(t *testing.T) {
	cfg := loadValues(t, "-f", writeValues(t, exampleValues(t)))

	for _, format := range keyFormats {
		t.Run(format.name, func(t *testing.T) {
			pki := newTestPKI(t)
			root := newFileRoot(t)

			certFile, keyFile, caFile := pki.files(t, format, cfg.Name, nil, serviceDNSName)
			root.write(t, cfg.KMIP.TLS.CertPath, certFile)
			root.write(t, cfg.KMIP.TLS.KeyPath, keyFile)
			root.write(t, cfg.KMIP.TLS.CAPath, caFile)

			server := config.TLSServer{
				CertPath: root.path(cfg.KMIP.TLS.CertPath),
				KeyPath:  root.path(cfg.KMIP.TLS.KeyPath),
				CAPath:   root.path(cfg.KMIP.TLS.CAPath),
			}
			serverTLS := must(server.BuildTLSConfig())(t)

			client := &tls.Config{
				Certificates: []tls.Certificate{clientCertificate(t, pki, format, "kmip-client")},
				RootCAs:      pki.rootPool(),
				ServerName:   serviceDNSName,
				MinVersion:   tls.VersionTLS12,
			}

			state, err := handshake(t.Context(), serverTLS, client)
			if err != nil {
				t.Fatalf("handshake with client certificate: %v", err)
			}

			if state.Version != tls.VersionTLS13 {
				t.Errorf("TLS version %x, want TLS 1.3", state.Version)
			}

			client.Certificates = nil
			if _, err := handshake(t.Context(), serverTLS, client); err == nil {
				t.Error("the KMIP server accepts a client without certificate")
			}
		})
	}
}

// handshake runs a TLS handshake between a server and a client with the configurations and
// returns the connection state of the server.
func handshake(ctx context.Context, server, client *tls.Config) (tls.ConnectionState, error) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	tlsServer := tls.Server(serverConn, server)
	tlsClient := tls.Client(clientConn, client)

	clientDone := make(chan error, 1)

	go func() {
		err := tlsClient.HandshakeContext(ctx)
		if err == nil {
			// TLS 1.3 clients finish before the server has checked their certificate: read
			// to receive its answer.
			_, err = tlsClient.Read(make([]byte, 1))
		}

		clientDone <- err
	}()

	serverErr := tlsServer.HandshakeContext(ctx)
	if serverErr == nil {
		_, serverErr = tlsServer.Write([]byte{0})
	}

	clientErr := <-clientDone

	return tlsServer.ConnectionState(), errors.Join(serverErr, clientErr)
}

// TestFilesMountExample checks that the files of the configuration examples are on the
// volumes of the extraVolumeMounts example, and that a file vault is on a writable volume.
func TestFilesMountExample(t *testing.T) {
	cfg := loadValues(t, "-f", writeValues(t, exampleValues(t)))
	mtls := must(config.GetAuthConfig(cfg.Auth.Config))(t)

	values := "extraVolumes:\n" + indent(valuesComment(t, "port, the KMIP server and a file vault:"), "  ") +
		"extraVolumeMounts:\n" + indent(valuesComment(t, "Example of the mounts for the volumes above:"), "  ")
	_, c := rootContainer(t, "-f", writeValues(t, values))

	mountOf := func(path string) (string, bool, bool) {
		for _, mount := range c.VolumeMounts {
			if strings.HasPrefix(path, strings.TrimSuffix(mount.MountPath, "/")+"/") {
				return mount.Name, mount.ReadOnly, true
			}
		}

		return "", false, false
	}

	files := []string{
		mtls.Server.CertPath, mtls.Server.KeyPath, mtls.Server.CAPath,
		mtls.Client.CertPath, mtls.Client.KeyPath, mtls.Client.CAPath,
		cfg.KMIP.TLS.CertPath, cfg.KMIP.TLS.KeyPath, cfg.KMIP.TLS.CAPath,
	}
	for _, file := range files {
		if _, _, found := mountOf(file); !found {
			t.Errorf("%s is not on a volume of the example", file)
		}
	}

	vault, ok := cfg.KeyBindings["K1"].VaultSpec.Config.(*sqlitevault.FileConfig)
	if !ok {
		t.Fatalf("the K1 example is not a file vault: %T", cfg.KeyBindings["K1"].VaultSpec.Config)
	}

	name, readOnly, found := mountOf(vault.Path)
	if !found || readOnly {
		t.Errorf("the file vault %s is not on a writable volume of the example (volume %q, read-only %t)",
			vault.Path, name, readOnly)
	}
}

// rootPool returns a pool with the root CA of the test PKI.
func (p *testPKI) rootPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.root.cert)

	return pool
}
