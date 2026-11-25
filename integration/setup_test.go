package integration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/ovh/kmip-go/payloads"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"

	_ "github.com/lib/pq"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/actions"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
	"github.com/openkcm/krypton/pkg/api/v1/proto/test/provider"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

// CLI test globals
var (
	binaryPath string
	coverDir   string
)

// Package-level infra instances built once in TestMain.
var (
	rootLevelInfra    services
	regionLevelInfra  services
	countryLevelInfra services
)

func TestMain(m *testing.M) {
	var cleanups []func()

	cliCleanups, err := setupCLI()
	cleanups = append(cleanups, cliCleanups...)
	if err != nil {
		runCleanups(cleanups)
		os.Exit(1)
	}

	infraCleanups, err := setupKRInfras()
	cleanups = append(cleanups, infraCleanups...)
	if err != nil {
		log.Printf("setupKRInfras: %v", err)
		runCleanups(cleanups)
		os.Exit(1)
	}

	exitCode := m.Run()
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

func setupPostgres(t *testing.T) string {
	t.Helper()
	ctx := t.Context()

	pgContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err, "failed to start PostgreSQL container")
	t.Cleanup(func() { _ = pgContainer.Terminate(ctx) })

	pgConnStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err, "failed to get PostgreSQL connection string")

	return pgConnStr
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
func newTenantStore(t *testing.T, db *sql.DB, n storesql.Node) store.Tenant {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t, n)
	}
	return storesql.NewTenantStore(db)
}

// newKeyStore creates a key store.
func newKeyStore(t *testing.T, db *sql.DB, n storesql.Node) store.Key {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t, n)
	}
	return storesql.NewKeyStore(db)
}

// newKeyVersionStore creates a keyversion store.
func newKeyVersionStore(t *testing.T, db *sql.DB, n storesql.Node) store.KeyVersion {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t, n)
	}
	return storesql.NewKeyVersionStore(db)
}

// newTransactor creates a transactor.
func newTransactor(t *testing.T, db *sql.DB, n storesql.Node) store.Transactor {
	t.Helper()
	if db == nil {
		db, _ = createDatabase(t, n)
	}
	return storesql.NewTransactor(db)
}

// createDatabase creates a new PostgreSQL database for testing and returns a connection to it.
func createDatabase(t *testing.T, n storesql.Node) (*sql.DB, string) {
	t.Helper()
	ctx := t.Context()

	// create a postgres database
	pgConnStr := setupPostgres(t)

	db, err := sql.Open("postgres", pgConnStr)
	require.NoError(t, err, "failed to connect to PostgreSQL")

	// migrate
	require.NoError(t, storesql.Migrate(ctx, db, n))

	return db, pgConnStr
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
	agentCerts     map[string]testAgentCert
}

// testAgentCert holds a client certificate and key in PEM format along with their file paths.
type testAgentCert struct {
	certPEM     []byte
	certPEMPath string
	keyPEM      []byte
	keyPEMPath  string
}

// newTestPKI generates a self-contained CA, server certificate, and client certificates for mTLS testing.
func newTestPKI(t *testing.T, agentNames ...string) *testPKI {
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

	serverCertPEM, serverKeyPEM := issueCert(
		t,
		caCert,
		caKey,
		pkix.Name{CommonName: "acme-corp"},
		false,
		[]net.IP{net.ParseIP(localHost)},
		makeURIs(t, "root"),
		false,
	)

	pki := &testPKI{
		caPEM:         caPEM,
		caCert:        caCert,
		caPrivateKey:  caKey,
		serverCertPEM: serverCertPEM,
		serverKeyPEM:  serverKeyPEM,
		agentCerts:    make(map[string]testAgentCert, len(agentNames)),
	}
	dir := t.TempDir()

	for _, n := range agentNames {
		uris := makeURIs(t, n)
		certPEM, keyPEM := issueCert(t, caCert, caKey, pkix.Name{CommonName: n}, true, nil, uris, false)
		tc := testAgentCert{certPEM: certPEM, keyPEM: keyPEM}

		tc.certPEMPath = filepath.Join(dir, n+"-cert.pem")
		writeFile(t, tc.certPEMPath, certPEM)

		tc.keyPEMPath = filepath.Join(dir, n+"-key.pem")
		writeFile(t, tc.keyPEMPath, keyPEM)

		pki.agentCerts[n] = tc
	}

	pki.caCertFilePath = filepath.Join(dir, "ca.pem")
	writeFile(t, pki.caCertFilePath, caPEM)

	pki.serverCertPath = filepath.Join(dir, "server.pem")
	writeFile(t, pki.serverCertPath, pki.serverCertPEM)

	pki.serverKeyPath = filepath.Join(dir, "server-key.pem")
	writeFile(t, pki.serverKeyPath, pki.serverKeyPEM)

	return pki
}

func (p *testPKI) issueClientCert(t *testing.T, cn string) testAgentCert {
	t.Helper()
	certPEM, keyPEM := issueCert(t, p.caCert, p.caPrivateKey, pkix.Name{CommonName: cn}, true, nil, nil, false)
	return testAgentCert{certPEM: certPEM, keyPEM: keyPEM}
}

// issueCert creates and signs a certificate (client or server) using the given CA.
func issueCert(
	t *testing.T,
	caCert *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	subject pkix.Name,
	client bool,
	ips []net.IP,
	uris []*url.URL,
	isExpired bool,
) (certPEM, keyPEM []byte) {
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
		URIs:         uris,
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

func makeURIs(t *testing.T, uris ...string) []*url.URL {
	t.Helper()
	result := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		parsed, err := url.Parse(makeKryptonID(u))
		require.NoError(t, err, "parse URI %s", u)
		result = append(result, parsed)
	}
	return result
}

// services maps region names to their running service instances.
type services map[string]*service

// service holds the running process, DB, and KMIP client for a single krypton node.
type service struct {
	name      string
	db        *sql.DB
	stores    *store.Stores
	cmd       *exec.Cmd
	port      string
	cfgPath   string
	dbConnStr string
	kmipPort  string
	pki       *testPKI
}

// Close terminates all service processes and releases resources.
func (s services) Close() {
	for _, srv := range s {
		srv.Close()
	}
}

// Close kills the process, closes the KMIP client, and closes the DB.
func (s *service) Close() {
	if s.cmd != nil {
		_ = s.cmd.Process.Kill()
	}
	if s.db != nil {
		_ = s.db.Close()
	}
}

// Find returns the service for the given region name, failing the test if not found.
func (s services) Find(t *testing.T, name string) *service {
	t.Helper()
	res, ok := s[name]
	require.True(t, ok)
	return res
}

// KMIPClient returns (or lazily creates) a KMIP client for the given region and tenant.
func (s services) KMIPClient(t *testing.T, name, tenantID string) *kmipclient.Client {
	t.Helper()
	res, ok := s[name]
	require.True(t, ok)

	require.NotNil(t, res.pki, "pki for service %s is nil", name)
	clientCerts := res.pki.issueClientCert(t, tenantID)

	cli := dialAs(t, localAddress(res.kmipPort), res.pki.caPEM, clientCerts.certPEM, clientCerts.keyPEM)

	t.Cleanup(func() {
		_ = cli.Close()
	})

	return cli
}

// grpcConn establishes an insecure gRPC client connection to the given port.
func grpcConn(t *testing.T, address string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(
		localAddress(address),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	return conn
}

// keyName generates a unique key name by appending a UUID to the given prefix.
func keyName(name string) string {
	return name + uuid.New().String()
}

// assertKeyStateAndStatus polls via gRPC until the key reaches the expected
// lifecycle state and processing status, failing after 10 seconds.
func assertKeyStateAndStatus(t *testing.T, cli keys.KeyServiceClient, tenantID, keyID string, state model.KeyLifeCycleState, status model.KeyProcessingStatus) {
	t.Helper()
	assert.Eventually(
		t,
		func() bool {
			r, err := cli.GetKey(t.Context(), &keys.GetKeyRequest{
				Id:       keyID,
				TenantId: tenantID,
			})
			require.NoError(t, err)
			assert.Equal(t, keyID, r.GetKey().GetId())
			return string(state) == r.GetKey().GetLifeCycleState() &&
				string(status) == r.GetKey().GetKeyProcessingState().GetStatus()
		},
		time.Second*10,
		200*time.Millisecond,
		"key %s in tenant %s did not reach state %s and status %s", keyID, tenantID, state, status)
}

// isJobFinished polls the action service until the job reaches Done status.
func isJobFinished(t *testing.T, aCli actions.ActionServiceClient, jobID string) {
	t.Helper()
	assert.Eventually(t, func() bool {
		r, err := aCli.GetAction(t.Context(), &actions.GetActionRequest{
			Id: jobID,
		})
		require.NoError(t, err)
		return r.GetAction().GetStatus() == string(orbital.JobGroupStatusDone)
	}, 60*time.Second, 200*time.Millisecond)
}

// compromiseKey marks a key (and optionally its children) as compromised.
func compromiseKey(t *testing.T, cli keys.KeyServiceClient, tenantID, keyID string, cascading bool) string {
	t.Helper()
	r, err := cli.CompromiseKey(t.Context(), &keys.CompromiseKeyRequest{
		Id:        keyID,
		TenantId:  tenantID,
		Cascading: cascading,
	})
	require.NoError(t, err)
	return r.GetJobGroupId()
}

// deactivateKey marks a key (and optionally its children) as deactivated.
func deactivateKey(t *testing.T, cli keys.KeyServiceClient, tenantID, keyID string, cascading bool) string {
	t.Helper()
	r, err := cli.DeactivateKey(t.Context(), &keys.DeactivateKeyRequest{
		Id:        keyID,
		TenantId:  tenantID,
		Cascading: cascading,
	})
	require.NoError(t, err)
	return r.GetJobGroupId()
}

// activateKey transitions a key to Active state, returns the job group ID.
func activateKey(t *testing.T, cli keys.KeyServiceClient, tenantID, keyID string, cascading bool) string {
	t.Helper()
	r, err := cli.ActivateKey(t.Context(), &keys.ActivateKeyRequest{
		Id:        keyID,
		TenantId:  tenantID,
		Cascading: cascading,
	})
	require.NoError(t, err)
	return r.GetJobGroupId()
}

func assertKMIPKeyFound(t *testing.T, cli *kmipclient.Client, tenantID, keyID string) *payloads.GetResponsePayload {
	t.Helper()
	key, err := getKMIPKey(t, cli, tenantID, keyID)
	assert.NoError(t, err, "Get")
	return key
}

func assertKMIPKeyNotFound(t *testing.T, cli *kmipclient.Client, tenantID, keyID string) {
	t.Helper()
	key, err := getKMIPKey(t, cli, tenantID, keyID)
	assert.Error(t, err, "Get")
	assert.Nil(t, key, "Expected nil key when not found")
}

// getKMIPKey retrieves key material from the KMIP endpoint of the specified region.
func getKMIPKey(t *testing.T, cli *kmipclient.Client, tenantID, keyID string) (*payloads.GetResponsePayload, error) {
	t.Helper()
	uid := tenantID + ":" + keyID + ":1"
	return cli.Get(uid).ExecContext(t.Context())
}

// suspendKey transitions a key (and optionally its children) to Suspended state.
func suspendKey(t *testing.T, cli keys.KeyServiceClient, tenantID, keyID string, cascading bool) string {
	t.Helper()
	r, err := cli.SuspendKey(t.Context(), &keys.SuspendKeyRequest{
		Id:        keyID,
		TenantId:  tenantID,
		Cascading: cascading,
	})
	require.NoError(t, err)
	return r.GetJobGroupId()
}

// createProviderAndBind registers a test provider instance and binds it to the given root key.
func createProviderAndBind(t *testing.T, rCli rootkey.ServiceClient, pCli provider.ServiceClient, tenantID, keyID string) {
	t.Helper()
	ctx := t.Context()
	instanceID := newStr("provider-instance")
	accessToken := newStr("access-token")
	providerKeyID := newStr("provider-key-1")

	_, err := pCli.UpsertInstance(ctx, &provider.UpsertInstanceRequest{
		InstanceId: instanceID,
	})
	require.NoError(t, err, "UpsertInstance")

	_, err = pCli.UpsertKey(ctx, &provider.UpsertKeyRequest{
		InstanceId: instanceID,
		KeyId:      providerKeyID,
	})
	require.NoError(t, err, "UpsertKey")

	_, err = pCli.UpsertKeyAuth(t.Context(), &provider.UpsertKeyAuthRequest{
		InstanceId:  instanceID,
		KeyId:       providerKeyID,
		AccessToken: accessToken,
	})
	require.NoError(t, err, "UpsertKeyAuth")

	_, err = rCli.CreateProvider(ctx, &rootkey.CreateProviderRequest{
		TenantId: tenantID,
		KeyId:    keyID,
		Provider: &rootkey.Provider{Provider: &rootkey.Provider_TestProvider{
			TestProvider: &rootkey.TestProvider{
				Config:      &rootkey.TestProviderConfig{InstanceId: instanceID},
				Auth:        &rootkey.TestProviderAuth{AccessToken: accessToken},
				ProviderKey: &rootkey.TestProviderKey{KeyId: providerKeyID},
			},
		}},
	})
	require.NoError(t, err)
}

// announceKey declares a new key in the hierarchy and returns its ID.
func announceKey(t *testing.T, cli keys.KeyServiceClient, req *keys.AnnounceKeyRequest) string {
	t.Helper()
	announceResp, err := cli.AnnounceKey(t.Context(), req)
	require.NoError(t, err)
	return announceResp.GetKey().GetId()
}

// createTenant provisions a new tenant and returns its ID.
func createTenant(t *testing.T, cli admin.TenantServiceClient, name string) string {
	t.Helper()
	r, err := cli.CreateTenant(t.Context(), &admin.CreateTenantRequest{
		Name: name,
	})
	require.NoError(t, err)
	return r.GetTenant().GetId()
}

// dekKind returns the kind string of the DEK key spec in the hierarchy.
func dekKind(ksps []spec.KeySpec) string {
	dekKind := ""
	for _, ksp := range ksps {
		if ksp.Role == spec.KeyRoleDek {
			dekKind = string(ksp.Kind)
		}
	}
	return dekKind
}

// cleanupCollector accumulates cleanup functions for use in TestMain
// where *testing.T is unavailable.
type cleanupCollector struct {
	fns []func()
}

func (c *cleanupCollector) add(fn func()) {
	c.fns = append(c.fns, fn)
}

func (c *cleanupCollector) makeTempDir() (string, error) {
	dir, err := os.MkdirTemp("", "kr-testmain-*")
	if err != nil {
		return "", fmt.Errorf("makeTempDir: %w", err)
	}
	c.fns = append(c.fns, func() { os.RemoveAll(dir) })
	return dir, nil
}

// setupKRInfras builds the root, region, and country level infras once for all tests.
// It returns cleanup functions to tear everything down after m.Run().
func setupKRInfras() ([]func(), error) {
	c := &cleanupCollector{}

	var err error
	if rootLevelInfra, err = initKRInfraServices(c, rootLevelConfig); err != nil {
		return c.fns, fmt.Errorf("root level: %w", err)
	}
	if regionLevelInfra, err = initKRInfraServices(c, regionLevelConfig); err != nil {
		return c.fns, fmt.Errorf("region level: %w", err)
	}
	if countryLevelInfra, err = initKRInfraServices(c, countryLevelConfig); err != nil {
		return c.fns, fmt.Errorf("country level: %w", err)
	}

	// Collect cleanups: infra Close first (kills processes, closes DBs),
	// then c.fns (terminates containers, removes temp dirs).
	var cleanups []func()
	cleanups = append(cleanups, c.fns...)
	cleanups = append(cleanups, rootLevelInfra.Close, regionLevelInfra.Close, countryLevelInfra.Close)

	return cleanups, nil
}

// ---------------------------------------------------------------------------
// init* helpers – standalone functions for TestMain (no *testing.T required).
// Each function returns an error rather than calling t.Fatal / panic.
// ---------------------------------------------------------------------------

func getFreePort() (string, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", localAddress("0"))
	if err != nil {
		return "", fmt.Errorf("getFreePort: %w", err)
	}
	defer l.Close()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return "", fmt.Errorf("getFreePort: unexpected address type: %T", l.Addr())
	}
	return strconv.Itoa(addr.Port), nil
}

func startPostgresContainer(c *cleanupCollector) (string, error) {
	ctx := context.Background()
	pgContainer, err := postgres.Run(ctx,
		"postgres:18-alpine",
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("startPostgresContainer: %w", err)
	}
	c.add(func() { _ = pgContainer.Terminate(ctx) })

	pgConnStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return "", fmt.Errorf("startPostgresContainer connstr: %w", err)
	}
	return pgConnStr, nil
}

func createTestDatabase(c *cleanupCollector, n storesql.Node) (*sql.DB, string, error) {
	pgConnStr, err := startPostgresContainer(c)
	if err != nil {
		return nil, "", err
	}
	db, err := sql.Open("postgres", pgConnStr)
	if err != nil {
		return nil, "", fmt.Errorf("createTestDatabase open: %w", err)
	}
	if err := storesql.Migrate(context.Background(), db, n); err != nil {
		return nil, "", fmt.Errorf("createTestDatabase migrate: %w", err)
	}
	return db, pgConnStr, nil
}

func writeTempConfigFile(c *cleanupCollector, pattern, content string) (string, error) {
	dir, err := c.makeTempDir()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", fmt.Errorf("writeTempConfigFile create: %w", err)
	}
	if _, err := f.WriteString(content); err != nil {
		return "", fmt.Errorf("writeTempConfigFile write: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("writeTempConfigFile close: %w", err)
	}
	return f.Name(), nil
}

func marshalYAML(a any) (string, error) {
	b, err := yaml.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("marshalYAML: %w", err)
	}
	return string(b), nil
}

func buildGoBinary(c *cleanupCollector, binaryName, sourceDir string) (string, error) {
	dir, err := c.makeTempDir()
	if err != nil {
		return "", err
	}
	binPath := filepath.Join(dir, binaryName)
	buildArgs := []string{"build", "-o", binPath}
	if coverDir != "" {
		buildArgs = append(buildArgs, "-cover", "-covermode=atomic")
	}
	buildArgs = append(buildArgs, sourceDir)
	buildCmd := exec.CommandContext(context.Background(), "go", buildArgs...)
	buildCmd.Stderr = os.Stderr
	if err := buildCmd.Run(); err != nil {
		return "", fmt.Errorf("buildGoBinary %s: %w", binaryName, err)
	}
	return binPath, nil
}

func newServiceCmd(c *cleanupCollector, path string, env []string) *exec.Cmd {
	cmd := exec.CommandContext(context.Background(), path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Env = append(os.Environ(), env...)
	if coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}
	c.add(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func waitForPortReady(port string) error {
	dialer := net.Dialer{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := dialer.DialContext(context.Background(), "tcp", localAddress(port))
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("waitForPortReady: server did not become ready on port %s", port)
}

func parseKryptonURIs(uris ...string) ([]*url.URL, error) {
	result := make([]*url.URL, 0, len(uris))
	for _, u := range uris {
		parsed, err := url.Parse(makeKryptonID(u))
		if err != nil {
			return nil, fmt.Errorf("parseKryptonURIs %s: %w", u, err)
		}
		result = append(result, parsed)
	}
	return result, nil
}

func issueTLSCert(
	caCert *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	subject pkix.Name,
	client bool,
	ips []net.IP,
	uris []*url.URL,
	isExpired bool,
) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("issueTLSCert gen key for %s: %w", subject.CommonName, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("issueTLSCert gen serial: %w", err)
	}

	notBefore := time.Now().Add(-time.Hour)
	notAfter := time.Now().Add(24 * time.Hour)
	if isExpired {
		notBefore = time.Now().Add(-48 * time.Hour)
		notAfter = time.Now().Add(-24 * time.Hour)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IPAddresses:  ips,
		URIs:         uris,
	}
	if client {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issueTLSCert sign cert for %s: %w", subject.CommonName, err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("issueTLSCert marshal key for %s: %w", subject.CommonName, err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func createTestPKI(c *cleanupCollector, agentNames ...string) (*testPKI, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("createTestPKI gen CA key: %w", err)
	}
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
	if err != nil {
		return nil, fmt.Errorf("createTestPKI sign CA: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("createTestPKI parse CA: %w", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	rootURIs, err := parseKryptonURIs("root")
	if err != nil {
		return nil, err
	}
	serverCertPEM, serverKeyPEM, err := issueTLSCert(
		caCert, caKey,
		pkix.Name{CommonName: "acme-corp"},
		false,
		[]net.IP{net.ParseIP(localHost)},
		rootURIs,
		false,
	)
	if err != nil {
		return nil, err
	}

	pki := &testPKI{
		caPEM:         caPEM,
		caCert:        caCert,
		caPrivateKey:  caKey,
		serverCertPEM: serverCertPEM,
		serverKeyPEM:  serverKeyPEM,
		agentCerts:    make(map[string]testAgentCert, len(agentNames)),
	}
	dir, err := c.makeTempDir()
	if err != nil {
		return nil, err
	}

	for _, n := range agentNames {
		uris, err := parseKryptonURIs(n)
		if err != nil {
			return nil, err
		}
		certPEM, keyPEM, err := issueTLSCert(caCert, caKey, pkix.Name{CommonName: n}, true, nil, uris, false)
		if err != nil {
			return nil, err
		}
		tc := testAgentCert{certPEM: certPEM, keyPEM: keyPEM}

		tc.certPEMPath = filepath.Join(dir, n+"-cert.pem")
		if err := os.WriteFile(tc.certPEMPath, certPEM, 0o600); err != nil {
			return nil, fmt.Errorf("createTestPKI write cert %s: %w", n, err)
		}

		tc.keyPEMPath = filepath.Join(dir, n+"-key.pem")
		if err := os.WriteFile(tc.keyPEMPath, keyPEM, 0o600); err != nil {
			return nil, fmt.Errorf("createTestPKI write key %s: %w", n, err)
		}

		pki.agentCerts[n] = tc
	}

	pki.caCertFilePath = filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(pki.caCertFilePath, caPEM, 0o600); err != nil {
		return nil, fmt.Errorf("createTestPKI write ca: %w", err)
	}

	pki.serverCertPath = filepath.Join(dir, "server.pem")
	if err := os.WriteFile(pki.serverCertPath, pki.serverCertPEM, 0o600); err != nil {
		return nil, fmt.Errorf("createTestPKI write server cert: %w", err)
	}

	pki.serverKeyPath = filepath.Join(dir, "server-key.pem")
	if err := os.WriteFile(pki.serverKeyPath, pki.serverKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("createTestPKI write server key: %w", err)
	}

	return pki, nil
}

func (s *service) initSetupKMIP(c *cleanupCollector) (config.KMIP, error) {
	if s.kmipPort == "" {
		port, err := getFreePort()
		if err != nil {
			return config.KMIP{}, err
		}
		s.kmipPort = port
	}
	pki, err := createTestPKI(c, s.name)
	if err != nil {
		return config.KMIP{}, err
	}
	s.pki = pki

	p, err := strconv.Atoi(s.kmipPort)
	if err != nil {
		return config.KMIP{}, fmt.Errorf("initSetupKMIP atoi: %w", err)
	}

	return config.KMIP{
		Name:     s.name,
		BindAddr: "127.0.0.1",
		Port:     p,
		TLS: config.TLSServer{
			CertPath: s.pki.serverCertPath,
			KeyPath:  s.pki.serverKeyPath,
			CAPath:   s.pki.caCertFilePath,
		},
	}, nil
}

// initAgentService creates a database, writes config, and prepares a command for an agent node.
func initAgentService(c *cleanupCollector, agentName, rootPort string) (*service, error) {
	db, connstr, err := createTestDatabase(c, storesql.Agent)
	if err != nil {
		return nil, fmt.Errorf("initAgentService %s db: %w", agentName, err)
	}

	cfg := config.AgentBootstrapConfig{
		Name: agentName,
		Role: config.AgentRole,
		KryptonRoot: config.KryptonRoot{
			Address: config.Address{
				Type: config.AddressTypeGRPC,
				URL:  localAddress(rootPort),
			},
		},
	}
	cfgYAML, err := marshalYAML(cfg)
	if err != nil {
		return nil, err
	}
	cfgPath, err := writeTempConfigFile(c, "agent-config-*.yaml", cfgYAML)
	if err != nil {
		return nil, err
	}

	bin, err := buildGoBinary(c, "agent", "../cmd/agent")
	if err != nil {
		return nil, err
	}

	agentPort, err := getFreePort()
	if err != nil {
		return nil, err
	}
	cmd := newServiceCmd(c, bin, []string{
		"AGENT_BOOTSTRAP_CONFIG_PATH=" + cfgPath,
		"AGENT_DATABASE_URL=" + connstr,
		"KRYPTON_TEK_KEY=" + testKeyBase64,
		"AGENT_PORT=" + agentPort,
	})

	return &service{
		name: agentName,
		db:   db,
		stores: &store.Stores{
			Tenants:     storesql.NewTenantStore(db),
			Agents:      storesql.NewAgentStore(db),
			Keys:        storesql.NewKeyStore(db),
			KeyVersions: storesql.NewKeyVersionStore(db),
		},
		cmd:       cmd,
		port:      agentPort,
		cfgPath:   cfgPath,
		dbConnStr: connstr,
	}, nil
}

// initRootService creates a database, writes config with connections to agents, and prepares a command for the root node.
func initRootService(
	c *cleanupCollector,
	cfg config.RootConfig,
	rootPort string,
	srvs services,
	env []string,
) (*service, error) {
	db, connstr, err := createTestDatabase(c, storesql.Root)
	if err != nil {
		return nil, fmt.Errorf("initRootService db: %w", err)
	}

	cfg.Connections = make(config.ConnectionConfigs, 0, len(srvs)+1)

	cfg.Connections = append(cfg.Connections, config.ConnectionConfig{
		Name: cfg.Name,
		Address: config.Address{
			Type: config.AddressTypeGRPC,
			URL:  localAddress(rootPort),
		},
	})

	for _, srv := range srvs {
		add := localAddress(srv.port)

		cfg.Connections = append(cfg.Connections, config.ConnectionConfig{
			Name: srv.name,
			Address: config.Address{
				Type: config.AddressTypeGRPC,
				URL:  add,
			},
		})

		if srv.kmipPort == "" {
			continue
		}

		kmipCfg, err := srv.initSetupKMIP(c)
		if err != nil {
			return nil, fmt.Errorf("initRootService kmip %s: %w", srv.name, err)
		}
		cfg.KMIPs = append(cfg.KMIPs, kmipCfg)
	}

	cfgYAML, err := marshalYAML(cfg)
	if err != nil {
		return nil, err
	}
	cfgPath, err := writeTempConfigFile(c, "root-config-*.yaml", cfgYAML)
	if err != nil {
		return nil, err
	}

	bin, err := buildGoBinary(c, regionRoot, "../cmd/root")
	if err != nil {
		return nil, err
	}

	providerDir, err := c.makeTempDir()
	if err != nil {
		return nil, err
	}

	cmd := newServiceCmd(c, bin, append([]string{
		"ROOT_CONFIG_PATH=" + cfgPath,
		"DATABASE_URL=" + connstr,
		"SERVER_PORT=" + rootPort,
		"KRYPTON_ROOT_KEY=" + testKeyBase64,
		"ENABLE_UNSAFE_TEST_PROVIDER=I_ACCEPT",
		"UNSAFE_TEST_PROVIDER_DIR=" + providerDir,
	}, env...))

	return &service{
		name: cfg.Name,
		db:   db,
		stores: &store.Stores{
			Tenants:     storesql.NewTenantStore(db),
			Agents:      storesql.NewAgentStore(db),
			Keys:        storesql.NewKeyStore(db),
			KeyVersions: storesql.NewKeyVersionStore(db),
		},
		cmd:       cmd,
		port:      rootPort,
		cfgPath:   cfgPath,
		dbConnStr: connstr,
	}, nil
}

// initKRInfraServices spins up a full krypton cluster (root + agents) based on the config.
func initKRInfraServices(c *cleanupCollector, cfg config.RootConfig, rootEnv ...string) (services, error) {
	rootPort, err := getFreePort()
	if err != nil {
		return nil, err
	}
	topology := cfg.Topology

	dk := dekKind(cfg.Hierarchy.KeySpecs)

	srvs := make(services, len(topology.Segments)+1)
	for _, seg := range topology.Segments {
		srv, err := initAgentService(c, seg.Name, rootPort)
		if err != nil {
			return nil, err
		}
		if seg.Segment.EndKind == dk {
			port, err := getFreePort()
			if err != nil {
				return nil, err
			}
			srv.kmipPort = port
		}
		srvs[seg.Name] = srv
	}

	var rootKMIP *service
	if cfg.Segment.EndKind == dk {
		rootKMIP = &service{name: cfg.Name}
		kmipCfg, err := rootKMIP.initSetupKMIP(c)
		if err != nil {
			return nil, err
		}
		cfg.KMIPs = append(cfg.KMIPs, kmipCfg)
	}

	rootService, err := initRootService(c, cfg, rootPort, srvs, rootEnv)
	if err != nil {
		return nil, err
	}
	if rootKMIP != nil {
		rootService.kmipPort = rootKMIP.kmipPort
		rootService.pki = rootKMIP.pki
	}

	if err := rootService.cmd.Start(); err != nil {
		return nil, fmt.Errorf("initKRInfraServices start root: %w", err)
	}
	if err := waitForPortReady(rootService.port); err != nil {
		return nil, err
	}

	for _, srv := range srvs {
		if err := srv.cmd.Start(); err != nil {
			return nil, fmt.Errorf("initKRInfraServices start agent %s: %w", srv.name, err)
		}
		if err := waitForPortReady(srv.port); err != nil {
			return nil, err
		}
	}

	srvs[regionRoot] = rootService
	return srvs, nil
}

func newStr(s string) string {
	return s + uuid.New().String()
}

// jobGroupRow represents a single row of CLI JSON output for a job group.
type jobGroupRow struct {
	ID string
}

// decodeJobGroup parses JSON output from the CLI into a jobGroupRow.
func decodeJobGroup(t *testing.T, output []byte) jobGroupRow {
	t.Helper()
	var rows []jobGroupRow
	err := json.Unmarshal(output, &rows)
	require.NoError(t, err, "failed to decode job group output: %s", string(output))
	require.NotEmpty(t, rows, "expected at least one job group row in output: %s", string(output))
	return rows[0]
}

// activateKeyCli activates a key via the CLI binary and returns the job group ID.
func activateKeyCli(t *testing.T, homeDir, port, tenantID, keyID string, cascading bool) string {
	t.Helper()
	return keyActionCli(t, "activate", homeDir, port, tenantID, keyID, cascading)
}

// suspendKeyCli suspend a key via the CLI binary and returns the job group ID.
func suspendKeyCli(t *testing.T, homeDir, port, tenantID, keyID string, cascading bool) string {
	t.Helper()
	return keyActionCli(t, "suspend", homeDir, port, tenantID, keyID, cascading)
}

// compromiseKeyCli marks a key as compromised via the CLI binary and returns the job group ID.
func compromiseKeyCli(t *testing.T, homeDir, port, tenantID, keyID string, cascading bool) string {
	t.Helper()
	return keyActionCli(t, "mark-compromised", homeDir, port, tenantID, keyID, cascading)
}

// deactivateKeyCli deactivates a key via the CLI binary and returns the job group ID.
func deactivateKeyCli(t *testing.T, homeDir, port, tenantID, keyID string, cascading bool) string {
	t.Helper()
	return keyActionCli(t, "deactivate", homeDir, port, tenantID, keyID, cascading)
}

func keyActionCli(t *testing.T, action, homeDir, port, tenantID, keyID string, cascading bool) string {
	t.Helper()
	ctx := t.Context()
	args := []string{
		action, "key",
		"--tenant-id", tenantID,
		"--key-id", keyID,
		"--json",
		"--server", "localhost:" + port,
	}
	if cascading {
		args = append(args, "--cascading")
	}

	cmd := newCLICommand(ctx, homeDir, args...)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "command should succeed, output: %s", string(output))
	r := decodeJobGroup(t, output)
	return r.ID
}
