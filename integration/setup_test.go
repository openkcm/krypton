package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/moby/moby/api/types/container"
	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// CLI test globals
var (
	binaryPath string
	coverDir   string
)

// Postgres test globals
var (
	pgConnStr string
)

func TestMain(m *testing.M) {
	var cleanups []func()

	cliCleanups, err := setupCLI()
	cleanups = append(cleanups, cliCleanups...)
	if err != nil {
		runCleanups(cleanups)
		os.Exit(1)
	}

	pgContainer, pgCleanups, err := setupPostgres()
	cleanups = append(cleanups, pgCleanups...)
	if err != nil {
		runCleanups(cleanups)
		os.Exit(1)
	}

	exitCode := m.Run()

	if exitCode != 0 {
		ctx := context.Background()
		reader, err := pgContainer.Logs(ctx)
		if err == nil {
			logs, _ := io.ReadAll(reader)
			fmt.Fprintf(os.Stderr, "\n=== PostgreSQL container logs ===\n%s\n", string(logs))
		}
	}

	runCleanups(cleanups)
	os.Exit(exitCode)
}

// setupCLI builds the CLI binary and sets up coverage directory. Returns cleanup functions.
func setupCLI() ([]func(), error) {
	ctx := context.Background()
	var cleanupFns []func()

	tmpDir, err := os.MkdirTemp("", "kr-integration-test-*")
	if err != nil {
		return nil, err
	}
	cleanupFn := func() { os.RemoveAll(tmpDir) }
	cleanupFns = append(cleanupFns, cleanupFn)

	binaryPath = filepath.Join(tmpDir, "kr")

	coverDir = os.Getenv("CLI_GOCOVERDIR")
	buildArgs := []string{"build", "-o", binaryPath}
	if coverDir != "" {
		buildArgs = append(buildArgs, "-cover", "-covermode=atomic")
	}
	buildArgs = append(buildArgs, "../cli")

	buildCmd := exec.CommandContext(ctx, "go", buildArgs...)
	buildCmd.Stderr = os.Stderr

	return cleanupFns, buildCmd.Run()
}

type stdoutLogConsumer struct{}

func (s *stdoutLogConsumer) Accept(l testcontainers.Log) {
	fmt.Print(string(l.Content))
}

// setupPostgres starts a PostgreSQL container and sets the global connection string. Returns cleanup functions.
func setupPostgres() (*postgres.PostgresContainer, []func(), error) {
	ctx := context.Background()
	var cleanupFns []func()

	pgContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		postgres.BasicWaitStrategies(),
		testcontainers.WithHostConfigModifier(func(hc *container.HostConfig) {
			hc.ShmSize = 256 * 1024 * 1024 // 256MB
		}),
		testcontainers.WithCmdArgs(
			"-c", "shared_buffers=64MB", // down from default 128MB
			"-c", "work_mem=2MB", // down from default 4MB, per-sort/hash
			"-c", "max_connections=50", // down from default 100
		),
		testcontainers.WithLogConsumers(&stdoutLogConsumer{}),
	)
	if err != nil {
		return nil, nil, err
	}
	cleanupFns = append(cleanupFns, func() { _ = pgContainer.Terminate(ctx) })

	pgConnStr, err = pgContainer.ConnectionString(ctx, "sslmode=disable")

	return pgContainer, cleanupFns, err
}

// runCleanups executes cleanup functions in reverse order.
func runCleanups(cleanups []func()) {
	for _, v := range slices.Backward(cleanups) {
		v()
	}
}

// newCLICommand creates a new exec.Command with the given arguments and sets up
// the environment variables including HOME and GOCOVERDIR (if coverage is enabled).
func newCLICommand(ctx context.Context, homeDir string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	cmd.Env = []string{"HOME=" + homeDir}
	if coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}
	return cmd
}

// newTenantStore creates a tenant store.
func newTenantStore(t *testing.T, db *sql.DB) store.Tenant {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t)
	}
	return storesql.NewTenantStore(db)
}

// newKeyStore creates a key store.
func newKeyStore(t *testing.T, db *sql.DB) store.Key {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t)
	}
	return storesql.NewKeyStore(db)
}

// newKeyVersionStore creates a keyversion store.
func newKeyVersionStore(t *testing.T, db *sql.DB) store.KeyVersion {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t)
	}
	return storesql.NewKeyVersionStore(db)
}

// newTransactor creates a transactor.
func newTransactor(t *testing.T, db *sql.DB) store.Transactor {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t)
	}
	return storesql.NewTransactor(db)
}

// createDatabase creates a new PostgreSQL database for testing and returns a connection to it.
func createDatabase(t *testing.T) (*sql.DB, string) {
	t.Helper()
	ctx := t.Context()

	pgContainer, pgCleanups, err := setupPostgres()
	var cleanups []func()
	cleanups = append(cleanups, pgCleanups...)
	if err != nil {
		runCleanups(cleanups)
		os.Exit(1)
	}

	t.Cleanup(func() {
		runCleanups(cleanups)
	})

	pgConnStr1, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("postgres", pgConnStr1)
	require.NoError(t, err, "failed to connect to PostgreSQL")

	dbName := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")

	_, err = db.ExecContext(ctx, "CREATE DATABASE "+dbName)
	if err != nil {
		db.Close()
		require.NoError(t, err, "failed to create test database")
	}
	db.Close()

	connStr := strings.Replace(pgConnStr1, "/postgres?", "/"+dbName+"?", 1)
	sqlDB, err := sql.Open("postgres", connStr)
	require.NoError(t, err, "failed to connect to test database")
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	t.Cleanup(func() {
		sqlDB.Close()

		db, err := sql.Open("postgres", pgConnStr1)
		if err == nil {
			_, _ = db.ExecContext(context.Background(), "DROP DATABASE "+dbName)
			db.Close()
		}
	})

	// migrate
	require.NoError(t, storesql.Migrate(ctx, sqlDB))

	return sqlDB, connStr
}

// RegisterFunc is a function that registers services to a gRPC server.
type RegisterFunc func(*grpc.Server)

// startGRPCServer starts a gRPC server and returns the server address.
// The register function is called to register services to the server.
// The server is automatically stopped when the test completes.
func startGRPCServer(t *testing.T, registerFns ...RegisterFunc) string {
	t.Helper()

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "localhost:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	srv := grpc.NewServer()
	for _, registerFn := range registerFns {
		registerFn(srv)
	}

	go func() {
		if err := srv.Serve(lis); err != nil {
			t.Logf("server stopped: %v", err)
		}
	}()

	t.Cleanup(func() {
		srv.GracefulStop()
	})

	return lis.Addr().String()
}

// defaultTestHierarchy mirrors the K0(root) → K1(kek) → K2(tek) → K3(dek)
// hierarchy used by the existing fixture builders below.
func defaultTestHierarchy() spec.KeyHierarchy {
	return spec.KeyHierarchy{
		Name: "test-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
		},
	}
}

// noopJobPreparer is a job preparer that only assigns a UUID if missing.
type noopJobPreparer struct{}

func (*noopJobPreparer) PrepareJob(_ context.Context, job orbital.Job) (orbital.Job, error) {
	if job.ID == uuid.Nil {
		job.ID = uuid.Must(uuid.NewUUID())
	}
	return job, nil
}

// testPKI is a self-contained CA + server cert + client cert(s) suitable for
// exercising mTLS in tests without touching the network.
type testPKI struct {
	caPEM          []byte
	caCert         *x509.Certificate
	caPrivateKey   *ecdsa.PrivateKey
	caCertFilePath string
	serverCertPEM  []byte
	serverCertPath string
	serverKeyPEM   []byte
	serverKeyPath  string
	clientCerts    map[string]testClientCert
}

// testClientCert holds a client certificate and key in PEM format along with their file paths.
type testClientCert struct {
	certPEM     []byte
	certPEMPath string
	keyPEM      []byte
	keyPEMPath  string
}

// newTestPKI generates a self-contained CA, server certificate, and client certificates for mTLS testing.
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

	serverCertPEM, serverKeyPEM := issueCert(t, caCert, caKey, pkix.Name{CommonName: "kmip-server"}, false, []net.IP{net.ParseIP(localHost)}, false)

	pki := &testPKI{
		caPEM:         caPEM,
		caCert:        caCert,
		caPrivateKey:  caKey,
		serverCertPEM: serverCertPEM,
		serverKeyPEM:  serverKeyPEM,
		clientCerts:   make(map[string]testClientCert, len(clientCNs)),
	}
	dir := t.TempDir()

	for _, cn := range clientCNs {
		certPEM, keyPEM := issueCert(t, caCert, caKey, pkix.Name{CommonName: cn}, true, nil, false)
		tc := testClientCert{certPEM: certPEM, keyPEM: keyPEM}

		tc.certPEMPath = filepath.Join(dir, cn+"-cert.pem")
		writeFile(t, tc.certPEMPath, certPEM)

		tc.keyPEMPath = filepath.Join(dir, cn+"-key.pem")
		writeFile(t, tc.keyPEMPath, keyPEM)

		pki.clientCerts[cn] = tc
	}

	pki.caCertFilePath = filepath.Join(dir, "ca.pem")
	writeFile(t, pki.caCertFilePath, caPEM)

	pki.serverCertPath = filepath.Join(dir, "server.pem")
	writeFile(t, pki.serverCertPath, pki.serverCertPEM)

	pki.serverKeyPath = filepath.Join(dir, "server-key.pem")
	writeFile(t, pki.serverKeyPath, pki.serverKeyPEM)

	return pki
}

// issueCert creates and signs a certificate (client or server) using the given CA.
func issueCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, subject pkix.Name, client bool, ips []net.IP, isExpired bool) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "gen key for %s", subject.CommonName)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err, "gen serial")

	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)
	if isExpired {
		notBefore = time.Now().Add(-48 * time.Hour)
		notAfter = time.Now().Add(-24 * time.Hour) // expired 24 hours ago
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
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

// writeFile writes data to path with 0600 permissions, failing the test on error.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, data, 0o600), "write %s", path)
}
