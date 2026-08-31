package integration

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ovh/kmip-go/kmipclient"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

const localHost = "127.0.0.1"

// testEnvironment holds the shared infrastructure for tests that require root + agent.
type testEnvironment struct {
	RootDB    *sql.DB
	AgentDB   *sql.DB
	RootPort  string
	AgentPort string
	Conn      *grpc.ClientConn
}

// testEnvWithRootKMIP holds the shared infrastructure for tests that require root and kmip server.
type testEnvWithRootKMIP struct {
	RootDB                  *sql.DB
	RootPort                string
	Conn                    *grpc.ClientConn
	PreConfiguredTenant     model.Tenant
	PreConfiguredKMIPClient *kmipclient.Client
}

// testEnvWithRootMTLS holds the shared infrastructure for tests that require a root server with mTLS.
type testEnvWithRootMTLS struct {
	allowedAgent string
	pki          *testPKI
	serverAddr   string
}

// testKey is a 32-byte AES-256 key for testing.
var testKey = []byte("01234567890123456789012345678901")

// testKeyBase64 is testKey encoded as base64 (standard encoding).
var testKeyBase64 = base64.StdEncoding.EncodeToString(testKey)

// setupEnvironment builds binaries, writes configs, starts root + agent, and returns
// a testEnvironment with open DB connections and a gRPC client to root.
func setupEnvironment(t *testing.T) *testEnvironment {
	t.Helper()

	rootDB, rootConnStr := createDatabase(t)
	agentDB, agentConnStr := createDatabase(t)
	rootPort := freePort(t)
	agentPort := freePort(t)

	rootCfgPath := writeRootConfig(t, "agent-k1", agentPort)
	agentCfgPath := writeAgentConfig(t, "agent-k1", "localhost:"+rootPort)

	rootBinary := buildBinary(t, "root", "../cmd/root")
	agentBinary := buildBinary(t, "agent", "../cmd/agent")

	rootCmd := createCmd(t, rootBinary, []string{
		"ROOT_CONFIG_PATH=" + rootCfgPath,
		"DATABASE_URL=" + rootConnStr,
		"SERVER_PORT=" + rootPort,
		"KRYPTON_ROOT_KEY=" + testKeyBase64,
	})
	require.NoError(t, rootCmd.Start(), "failed to start root server")
	waitForPort(t, rootPort)

	agentCmd := createCmd(t, agentBinary, []string{
		"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
		"AGENT_DATABASE_URL=" + agentConnStr,
		"AGENT_PORT=" + agentPort,
	})
	require.NoError(t, agentCmd.Start(), "failed to start agent")
	waitForPort(t, agentPort)

	conn, err := grpc.NewClient(
		localAddress(rootPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	return &testEnvironment{
		RootDB:    rootDB,
		AgentDB:   agentDB,
		RootPort:  rootPort,
		AgentPort: agentPort,
		Conn:      conn,
	}
}

// setupRootEnvWithMTLS builds the root binary, starts a root server with mTLS enabled,
// and returns a testEnvWithRootMTLS with both mTLS and non-mTLS gRPC connections.
func setupRootEnvWithMTLS(t *testing.T) *testEnvWithRootMTLS {
	t.Helper()

	_, rootConnStr := createDatabase(t)
	rootPort := freePort(t)

	allowedAgent := "allowed-agent" + uuid.NewString()
	pki := newTestPKI(t, allowedAgent)

	rootCfgPath := writeRootConfigWithMTLS(t, pki.serverCertPath, pki.serverKeyPath, pki.caCertFilePath, allowedAgent)

	rootBinary := buildBinary(t, "root", "../cmd/root")

	rootCmd := createCmd(t, rootBinary, []string{
		"ROOT_CONFIG_PATH=" + rootCfgPath,
		"DATABASE_URL=" + rootConnStr,
		"SERVER_PORT=" + rootPort,
		"KRYPTON_ROOT_KEY=" + testKeyBase64,
	})
	require.NoError(t, rootCmd.Start(), "failed to start root server")
	waitForPort(t, rootPort)

	return &testEnvWithRootMTLS{
		serverAddr:   localAddress(rootPort),
		allowedAgent: allowedAgent,
		pki:          pki,
	}
}

// setupRootEnvWithKMIP builds the root binary, starts a root server with KMIP enabled,
// pre-configures a tenant, and returns a testEnvWithRootKMIP with gRPC and KMIP clients.
func setupRootEnvWithKMIP(t *testing.T) *testEnvWithRootKMIP {
	t.Helper()

	rootDB, rootConnStr := createDatabase(t)
	rootPort := freePort(t)
	kmipRootPort := freePort(t)

	// preconfiguring a tenant
	ctr, err := newTenantStore(t, rootDB).CreateTenant(t.Context(), store.CreateTenantQuery{
		Tenant: model.NewTenant("preconfigured-tenant-"+uuid.NewString(), nil),
	})
	require.NoError(t, err)
	tenant := ctr.Tenant

	pki := newTestPKI(t, tenant.ID)
	rootCfgPath := writeRootConfigWithKMIP(t, kmipRootPort, pki.serverCertPath, pki.serverKeyPath, pki.caCertFilePath)

	rootBinary := buildBinary(t, "root", "../cmd/root")

	rootCmd := createCmd(t, rootBinary, []string{
		"ROOT_CONFIG_PATH=" + rootCfgPath,
		"DATABASE_URL=" + rootConnStr,
		"SERVER_PORT=" + rootPort,
		"KRYPTON_ROOT_KEY=" + testKeyBase64,
	})
	require.NoError(t, rootCmd.Start(), "failed to start root server")
	waitForPort(t, rootPort)

	conn, err := grpc.NewClient(
		"localhost:"+rootPort,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	kmipAddr := "localhost:" + kmipRootPort
	waitTCPReady(t, kmipAddr)

	kmipCli := dialAs(t, kmipAddr, pki, tenant.ID)
	t.Cleanup(func() { _ = kmipCli.Close() })
	return &testEnvWithRootKMIP{
		RootDB:                  rootDB,
		RootPort:                rootPort,
		Conn:                    conn,
		PreConfiguredTenant:     tenant,
		PreConfiguredKMIPClient: kmipCli,
	}
}

// writeRootConfig writes a root config YAML to a temp file and returns the path.
func writeRootConfig(t *testing.T, agentName, agentPort string) string {
	t.Helper()

	content := fmt.Sprintf(`name: root
role: root
segment:
  start_kind: K0
  end_kind: K1
selector_labels:
  environment: production
key_bindings:
  K0:
    sealer:
      name: root-sealer
      type: aes256gcm-staticsecret
      config:
        secret:
          type: envvar
          config:
            name: KRYPTON_ROOT_KEY
  K1:
    crypto:
      name: kek-crypto
      type: aes256gcm
    vault:
      name: root-vault
      type: unsafe-sqlite-memory
hierarchy:
  name: test-hierarchy
  key_specs:
    - kind: K0
      role: root
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K1
      role: kek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K2
      role: tek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K3
      role: dek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
topology:
  segments:
    - name: %s
      segment:
        start_kind: K2
        end_kind: K3
      key_bindings:
        K2:
          sealer:
            name: agent-sealer
            type: aes256gcm-staticsecret
            config:
              secret:
                type: envvar
                config:
                  name: KRYPTON_TEK_KEY
          crypto:
            name: agent-crypto
            type: aes256gcm
          vault:
            name: agent-vault
            type: unsafe-sqlite-memory
          parent_key_provider:
            agent_name: root
        K3:
          crypto:
            name: agent-dek-crypto
            type: aes256gcm
          vault:
            name: agent-dek-vault
            type: unsafe-sqlite-memory
      selector_labels:
        cloud: aws
reconciler:
  execInterval: 500ms
  targets:
    - name: %s
      address: localhost:%s
`, agentName, agentName, agentPort)

	return writeTempFile(t, "root-config-*.yaml", content)
}

// writeRootConfigWithKMIP writes a root config YAML with KMIP settings to a temp file and returns the path.
func writeRootConfigWithKMIP(t *testing.T, kmipPort, kmipServerCertPath, kmipServerKeyPath, kmipClientCAPath string) string {
	t.Helper()

	content := fmt.Sprintf(`name: root
role: root
segment:
  start_kind: K0
  end_kind: K2
selector_labels:
  environment: production
key_bindings:
  K0:
    sealer:
      name: root-sealer
      type: aes256gcm-staticsecret
      config:
        secret:
          type: envvar
          config:
            name: KRYPTON_ROOT_KEY
  K1:
    crypto:
      name: kek-crypto
      type: aes256gcm
    vault:
      name: k1-vault
      type: unsafe-sqlite-memory
  K2:
    crypto:
      name: dek-crypto
      type: aes256gcm
    vault:
      name: k2-vault
      type: unsafe-sqlite-memory
hierarchy:
  name: test-hierarchy
  key_specs:
    - kind: K0
      role: root
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K1
      role: kek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K2
      role: dek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
topology:
kmip:
  bind_addr: localhost
  port: %s
  tls:
    cert_path: %s
    key_path: %s
    ca_path: %s
`, kmipPort, kmipServerCertPath, kmipServerKeyPath, kmipClientCAPath)

	return writeTempFile(t, "root-config-*.yaml", content)
}

// writeRootAgentConfigWithMTLS writes a root config YAML with mTLS settings for an agent to a temp file and returns the path.
func writeRootAgentConfigWithMTLS(t *testing.T, agentName, serverCertPath, serverKeyPath, clientCAPath string) string {
	t.Helper()

	content := fmt.Sprintf(`name: root
role: root
segment:
  start_kind: K0
  end_kind: K1
selector_labels:
  environment: production
key_bindings:
  K0:
    sealer:
      name: root-sealer
      type: aes256gcm-staticsecret
      config:
        secret:
          type: envvar
          config:
            name: KRYPTON_ROOT_KEY
  K1:
    crypto:
      name: kek-crypto
      type: aes256gcm
    vault:
      name: root-vault
      type: unsafe-sqlite-memory
hierarchy:
  name: test-hierarchy
  key_specs:
    - kind: K0
      role: root
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K1
      role: kek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K2
      role: tek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K3
      role: dek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
topology:
  segments:
    - name: %s
      segment:
        start_kind: K2
        end_kind: K3
      key_bindings:
        K2:
          sealer:
            name: agent-sealer
            type: aes256gcm-staticsecret
            config:
              secret:
                type: envvar
                config:
                  name: KRYPTON_TEK_KEY
          crypto:
            name: agent-crypto
            type: aes256gcm
          vault:
            name: agent-vault
            type: unsafe-sqlite-memory
          parent_key_provider:
            agent_name: root
        K3:
          crypto:
            name: agent-dek-crypto
            type: aes256gcm
          vault:
            name: agent-dek-vault
            type: unsafe-sqlite-memory
      selector_labels:
        cloud: aws
auth:
  type: mtls
  config:
    server:
      cert_path: %s
      key_path: %s
      ca_path: %s
    client:
      cert_path: dummy
      key_path: dummy
      ca_path: dummy
  identities:
    - name: %s
      uri: %s
`, agentName, serverCertPath, serverKeyPath, clientCAPath, agentName, makeKryptonID(agentName))

	return writeTempFile(t, "root-config-*.yaml", content)
}

// writeRootConfigWithMTLS writes a root config YAML with mTLS settings to a temp file and returns the path.
func writeRootConfigWithMTLS(t *testing.T, serverCertPath, serverKeyPath, clientCAPath, allowedAgent string) string {
	t.Helper()

	content := fmt.Sprintf(`name: root
role: root
segment:
  start_kind: K0
  end_kind: K2
selector_labels:
  environment: production
key_bindings:
  K0:
    sealer:
      name: root-sealer
      type: aes256gcm-staticsecret
      config:
        secret:
          type: envvar
          config:
            name: KRYPTON_ROOT_KEY
  K1:
    crypto:
      name: kek-crypto
      type: aes256gcm
    vault:
      name: k1-vault
      type: unsafe-sqlite-memory
  K2:
    crypto:
      name: dek-crypto
      type: aes256gcm
    vault:
      name: k2-vault
      type: unsafe-sqlite-memory
hierarchy:
  name: test-hierarchy
  key_specs:
    - kind: K0
      role: root
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K1
      role: kek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
    - kind: K2
      role: dek
      algorithm: AES256
      labels_spec:
        allow_user_labels: true
topology:
auth:
  type: mtls
  config:
    server:
      cert_path: %s
      key_path: %s
      ca_path: %s
    client:
      cert_path: dummy
      key_path: dummy
      ca_path: dummy
  identities:
    - name: %s
      uri: %s
`, serverCertPath, serverKeyPath, clientCAPath, allowedAgent, makeKryptonID(allowedAgent))

	return writeTempFile(t, "root-config-*.yaml", content)
}

// writeAgentConfig writes an agent bootstrap config YAML to a temp file and returns the path.
func writeAgentConfig(t *testing.T, agentName, rootAddress string) string {
	t.Helper()

	content := fmt.Sprintf(`name: %s
role: agent
krypton_root:
  address:
    type: grpc
    url: %s
`, agentName, rootAddress)

	return writeTempFile(t, "agent-config-*.yaml", content)
}

// writeAgentConfigWithMTLS writes an agent bootstrap config YAML with mTLS settings to a temp file and returns the path.
func writeAgentConfigWithMTLS(t *testing.T, agentName, rootAddress, clientCertPath, clientKeyPath, serverCAPath string) string {
	t.Helper()
	content := fmt.Sprintf(`name: %s
role: agent
krypton_root:
  address:
    type: grpc
    url: %s
auth:
  type: mtls
  config:
    client:
      cert_path: %s
      key_path: %s
      ca_path: %s
    server:
      cert_path: dummy
      key_path: dummy
      ca_path: dummy
`, agentName, rootAddress, clientCertPath, clientKeyPath, serverCAPath)

	return writeTempFile(t, "agent-config-*.yaml", content)
}

// insertTenant inserts a tenant row directly into a database to satisfy FK constraints.
func insertTenant(t *testing.T, db *sql.DB, tenantID, tenantName string) {
	t.Helper()
	now := time.Now().UnixNano()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO tenants (id, name, labels, created_at, updated_at) VALUES ($1, $2, '{}', $3, $4)`,
		tenantID, tenantName, now, now,
	)
	require.NoError(t, err, "failed to insert tenant into database")
}

// insertActiveParentKey inserts an Active key directly into the root DB so it
// can serve as the parent for an AnnounceKey call. Used by integration tests
// to bypass the multi-step parent announce flow when only the child path is
// under test.
func insertActiveParentKey(t *testing.T, db *sql.DB, tenantID, kind string) string {
	t.Helper()
	keyID := uuid.NewString()
	insertActiveParentKeyWithID(t, db, tenantID, kind, keyID)
	return keyID
}

// insertActiveParentKeyWithID is the same as insertActiveParentKey but lets
// the caller pin the key ID — used to mirror a parent key into both root and
// agent databases when the agent's CreateKey FK on (tenant_id, parent_id)
// requires it.
func insertActiveParentKeyWithID(t *testing.T, db *sql.DB, tenantID, kind, keyID string) {
	t.Helper()
	now := time.Now().UnixNano()
	_, err := db.ExecContext(
		t.Context(),
		`INSERT INTO keys (id, tenant_id, kind, name, parent_id, managed_by, labels, life_cycle_state, processing_status, processing_job_id, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, NULL, $5, '{}', $6, $7, NULL, $8, $9)`,
		keyID, tenantID, kind, "parent-"+keyID, "root", "active", "completed", now, now,
	)
	require.NoError(t, err, "failed to insert active parent key")
}

// awaitJobStatus polls the jobs table until the job with the given external ID
// reaches the expected status. Fails the test if the timeout is exceeded.
func awaitJobStatus(t *testing.T, db *sql.DB, externalID, expectedStatus string, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		var status string
		err := db.QueryRowContext(
			ctx,
			"SELECT status FROM jobs WHERE external_id = $1", externalID,
		).Scan(&status)
		if err == nil && status == expectedStatus {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for job with external_id=%s to reach status %s", externalID, expectedStatus)
		case <-ticker.C:
		}
	}
}

// awaitKeyExists polls the keys table until a key with the given ID and tenant exists.
// Fails the test if the timeout is exceeded.
func awaitKeyExists(t *testing.T, db *sql.DB, keyID, tenantID string, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		var id string
		err := db.QueryRowContext(
			ctx,
			"SELECT id FROM keys WHERE id = $1 AND tenant_id = $2", keyID, tenantID,
		).Scan(&id)
		if err == nil {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for key %s to appear in agent database", keyID)
		case <-ticker.C:
		}
	}
}

// awaitKeyProcessingStatusViaGRPC polls the root admin gRPC API until the key's
// processing status reaches expected. Fails the test if the timeout is exceeded.
func awaitKeyProcessingStatusViaGRPC(t *testing.T, cli keys.KeyServiceClient, keyID, tenantID, expected string, timeout time.Duration) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		resp, err := cli.GetKey(ctx, &keys.GetKeyRequest{Id: keyID, TenantId: tenantID})
		if err == nil && resp.GetKey().GetKeyProcessingState().GetStatus() == expected {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for key %s to reach processing status %s", keyID, expected)
		case <-ticker.C:
		}
	}
}

// writeTempFile writes content to a temporary file matching pattern and returns the path.
func writeTempFile(t *testing.T, pattern, content string) string {
	t.Helper()
	dir := t.TempDir()

	f, err := os.CreateTemp(dir, pattern)
	require.NoError(t, err)

	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	return f.Name()
}

// seedSelectedTenant writes a state.lock file in homeDir/.krypton with the given tenant selection.
func seedSelectedTenant(t *testing.T, homeDir, tenantID, tenantName string) {
	t.Helper()
	dir := filepath.Join(homeDir, ".krypton")
	require.NoError(t, os.MkdirAll(dir, 0700))
	payload := fmt.Appendf(nil, `{"tenant":{"id":%q,"name":%q}}`, tenantID, tenantName)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "state.lock"), payload, 0600))
}

// waitTCPReady polls the given address until a TCP connection succeeds or 2s timeout is exceeded.
func waitTCPReady(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var d net.Dialer
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		conn, err := d.DialContext(ctx, "tcp", addr)
		cancel()
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("KMIP server did not start listening on %s in time", addr)
}

// dialAs creates a KMIP client authenticated with the certificate for the given CN.
func dialAs(t *testing.T, addr string, pki *testPKI, cn string) *kmipclient.Client {
	t.Helper()
	cc, ok := pki.agentCerts[cn]
	require.True(t, ok, "no client cert for CN %q", cn)
	c, err := kmipclient.Dial(
		addr,
		kmipclient.WithRootCAPem(pki.caPEM),
		kmipclient.WithClientCertPEM(cc.certPEM, cc.keyPEM),
		kmipclient.WithServerName(localHost),
	)
	require.NoError(t, err, "Dial as %s", cn)
	return c
}

// loginNoAuth runs the CLI command `krypton login no-auth` in a temp dir and asserts it succeeds.
func loginNoAuth(t *testing.T, homeDir string) {
	t.Helper()

	cmd := newCLICommand(
		t.Context(),
		homeDir,
		"login",
		"no-auth")
	output, err := cmd.CombinedOutput()

	// then
	require.NoError(t, err, "command should succeed, output: %s", string(output))
}

// waitForPort polls the given port until a TCP connection succeeds or 10s timeout is exceeded.
func waitForPort(t *testing.T, port string) {
	t.Helper()

	ctx := t.Context()

	dialer := net.Dialer{Timeout: time.Second}
	require.Eventually(t, func() bool {
		conn, err := dialer.DialContext(ctx, "tcp", localAddress(port))
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 10*time.Second, 100*time.Millisecond, "server did not become ready on port "+port)
}

// buildBinary builds a Go binary from sourceDir and returns the path to the built binary.
func buildBinary(t *testing.T, binaryName string, sourceDir string) string {
	t.Helper()

	ctx := t.Context()

	binaryPath := filepath.Join(t.TempDir(), binaryName)

	buildArgs := []string{"build", "-o", binaryPath}
	if coverDir != "" {
		buildArgs = append(buildArgs, "-cover", "-covermode=atomic")
	}
	buildArgs = append(buildArgs, sourceDir)

	buildCmd := exec.CommandContext(ctx, "go", buildArgs...)
	buildCmd.Stderr = os.Stderr

	err := buildCmd.Run()
	require.NoError(t, err, "failed to build agent binary")

	return binaryPath
}

// freePort is useful for tests that need to start a server on a random port.
func freePort(t *testing.T) string {
	t.Helper()

	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", localAddress("0"))
	require.NoError(t, err, "failed to find a free port")

	defer l.Close()

	addr, ok := l.Addr().(*net.TCPAddr)
	require.True(t, ok, "unexpected address type: %T", l.Addr())

	return strconv.Itoa(addr.Port)
}

// createCmd creates an exec.Cmd for the given binary path and environment variables, and sets up cleanup.
func createCmd(t *testing.T, path string, env []string) *exec.Cmd {
	t.Helper()
	ctx := t.Context()
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Env = append(os.Environ(),
		env...,
	)
	if coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}

	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	return cmd
}

func localAddress(port string) string {
	return net.JoinHostPort(localHost, port)
}

func makeKryptonID(uri string) string {
	return "kryptonid://acme-corp/service/" + uri
}
