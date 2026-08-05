package integration

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
)

// testEnvironment holds the shared infrastructure for tests that require root + agent.
type testEnvironment struct {
	RootDB    *sql.DB
	AgentDB   *sql.DB
	RootPort  string
	AgentPort string
	Conn      *grpc.ClientConn
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
		"ROOT_SERVER_PORT=" + rootPort,
	})
	require.NoError(t, agentCmd.Start(), "failed to start agent")
	waitForPort(t, agentPort)

	conn, err := grpc.NewClient(
		"localhost:"+rootPort,
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

// writeRootConfig writes a valid root config YAML to a temp file with the given
// agent as a reconciler target and returns the file path.
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

func seedSelectedTenant(t *testing.T, homeDir, tenantID, tenantName string) {
	t.Helper()
	dir := filepath.Join(homeDir, ".krypton")
	require.NoError(t, os.MkdirAll(dir, 0700))
	payload := fmt.Appendf(nil, `{"tenant":{"id":%q,"name":%q}}`, tenantID, tenantName)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "state.lock"), payload, 0600))
}
