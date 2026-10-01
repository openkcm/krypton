package integration

import (
	"encoding/json/v2"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/store/sql"
)

func TestAnnounceKey(t *testing.T) {
	env := setupEnvironment(t)

	tenantCli := admin.NewTenantServiceClient(env.Conn)
	keyCli := keypb.NewKeyServiceClient(env.Conn)

	t.Run("should announce root-managed key and complete via job group", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-root-test-" + uuid.New().String(),
		})
		require.NoError(t, err)
		tenantID := tenantResp.GetTenant().GetId()

		keyName := "root-key-" + uuid.New().String()
		resp, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K0",
			Name:       keyName,
			TargetName: "",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)

		keyID := resp.GetKey().GetId()
		assert.Equal(t, "root", resp.GetKey().GetManagedBy())
		assert.Equal(t, "pending", resp.GetKey().GetKeyProcessingState().GetStatus())

		awaitJobStatus(t, env.RootDB, keyName, "DONE", 15*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, keyID, tenantID, "completed", 15*time.Second)
	})

	t.Run("should announce key to agent and complete job", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-test-" + uuid.New().String(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		tenantName := tenantResp.GetTenant().GetName()

		insertTenant(t, env.AgentDB, tenantID, tenantName)
		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")

		keyName := "test-key-" + uuid.New().String()
		resp, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			ParentId:   parentID,
			TargetName: "agent-k1",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)

		keyID := resp.GetKey().GetId()
		assert.Equal(t, "pre-activation", resp.GetKey().GetLifeCycleState())
		assert.Equal(t, "agent-k1", resp.GetKey().GetManagedBy())
		// AnnounceKey returns the persisted state — Pending for agent-managed.
		// ConfirmJob flips Pending→InProgress and OnJobDone settles to Completed.
		assert.Equal(t, "pending", resp.GetKey().GetKeyProcessingState().GetStatus())

		awaitKeyExists(t, env.AgentDB, keyID, tenantID, 10*time.Second)
		awaitJobStatus(t, env.RootDB, keyName, "DONE", 15*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, keyID, tenantID, "completed", 15*time.Second)
	})

	t.Run("should be idempotent on duplicate (tenant, name)", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "idempotent-test-" + uuid.New().String(),
		})
		require.NoError(t, err)
		tenantID := tenantResp.GetTenant().GetId()
		insertTenant(t, env.AgentDB, tenantID, tenantResp.GetTenant().GetName())
		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")

		keyName := "idempotent-key-" + uuid.New().String()
		first, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			ParentId:   parentID,
			TargetName: "agent-k1",
		})
		require.NoError(t, err)
		require.NotEmpty(t, first.GetKey().GetId())

		// Wait for the first job linkage to be persisted before retrying.
		awaitKeyProcessingStatusViaGRPC(t, keyCli, first.GetKey().GetId(), tenantID, "completed", 15*time.Second)

		second, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			ParentId:   parentID,
			TargetName: "agent-k1",
		})
		require.NoError(t, err)

		assert.Equal(t, first.GetKey().GetId(), second.GetKey().GetId())
		assert.Equal(t, first.GetKey().GetKeyProcessingState().GetJobId(), second.GetKey().GetKeyProcessingState().GetJobId())
	})

	t.Run("failed retry recovers once conflicting key is removed", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-recover-test-" + uuid.New().String(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		insertTenant(t, env.AgentDB, tenantID, tenantResp.GetTenant().GetName())
		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")

		keyName := "recover-key-" + uuid.New().String()
		// A key with the same (tenant, name) but a different kind already lives
		// on the agent → the announce's UpsertKey is rejected with a terminal
		// ErrKeyConflict → job FAILED → key processing Failed.
		insertKey(t, env.AgentDB, model.NewKey(tenantID, keyName, "K3", &parentID, "agent-k1", nil))

		first, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			ParentId:   parentID,
			TargetName: "agent-k1",
		})
		require.NoError(t, err)
		keyID := first.GetKey().GetId()

		awaitJobStatus(t, env.RootDB, keyName, "FAILED", 15*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, keyID, tenantID, "failed", 15*time.Second)

		// Remove the conflicting key so the retry can create the announced key.
		deleteKey(t, env.AgentDB, tenantID, keyName)

		retry, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			ParentId:   parentID,
			TargetName: "agent-k1",
		})
		require.NoError(t, err)
		assert.Equal(t, keyID, retry.GetKey().GetId(), "retry must reuse the existing key.ID")

		awaitKeyExists(t, env.AgentDB, keyID, tenantID, 10*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, keyID, tenantID, "completed", 15*time.Second)
	})

	t.Run("should announce agent-managed key via CLI and complete job for an existing tenant in agent", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-cli-test-" + uuid.New().String(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		tenantName := tenantResp.GetTenant().GetName()

		insertTenant(t, env.AgentDB, tenantID, tenantName)
		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")

		homeDir := t.TempDir()
		// login with no auth
		loginNoAuth(t, homeDir)

		seedSelectedTenant(t, homeDir, tenantID, tenantName)

		keyName := "cli-key-" + uuid.New().String()
		cmd := newCLICommand(ctx, homeDir, "announce", "key",
			"--kind", "K2",
			"--name", keyName,
			"--parent", parentID,
			"--target-name", "agent-k1",
			"--label", "cloud=aws",
			"--json",
			"--server", "localhost:"+env.RootPort,
		)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))

		rows := decodeAnnouncedKey(t, output)
		require.Len(t, rows, 1)
		key := rows[0]

		assert.Equal(t, "K2", key.Kind)
		assert.Equal(t, keyName, key.Name)
		assert.Equal(t, parentID, key.ParentID)
		assert.Equal(t, "agent-k1", key.ManagedBy)
		assert.Equal(t, "pending", key.Status)
		assert.NotEmpty(t, key.ID)

		awaitKeyExists(t, env.AgentDB, key.ID, tenantID, 10*time.Second)
		awaitJobStatus(t, env.RootDB, keyName, "DONE", 15*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, key.ID, tenantID, "completed", 15*time.Second)
	})

	t.Run("should announce agent-managed key via CLI and complete job for a non existing tenant in agent", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-cli-test-" + uuid.New().String(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		tenantName := tenantResp.GetTenant().GetName()

		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")

		homeDir := t.TempDir()
		// login with no auth
		loginNoAuth(t, homeDir)

		seedSelectedTenant(t, homeDir, tenantID, tenantName)

		// check if tenant is not present in agent db
		agentTenantStore := sql.NewTenantStore(env.AgentDB)
		_, err = agentTenantStore.GetTenant(ctx, store.GetTenantQuery{
			ID: tenantID,
		})
		assert.ErrorIs(t, err, store.ErrTenantNotFound, "tenant should not be present in agent db")

		keyName := "cli-key-" + uuid.New().String()
		cmd := newCLICommand(ctx, homeDir, "announce", "key",
			"--kind", "K2",
			"--name", keyName,
			"--parent", parentID,
			"--target-name", "agent-k1",
			"--label", "cloud=aws",
			"--json",
			"--server", "localhost:"+env.RootPort,
		)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))

		rows := decodeAnnouncedKey(t, output)
		require.Len(t, rows, 1)
		key := rows[0]

		assert.Equal(t, "K2", key.Kind)
		assert.Equal(t, keyName, key.Name)
		assert.Equal(t, parentID, key.ParentID)
		assert.Equal(t, "agent-k1", key.ManagedBy)
		assert.Equal(t, "pending", key.Status)
		assert.NotEmpty(t, key.ID)

		awaitKeyExists(t, env.AgentDB, key.ID, tenantID, 10*time.Second)
		awaitJobStatus(t, env.RootDB, keyName, "DONE", 15*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, key.ID, tenantID, "completed", 15*time.Second)

		aTenantRes, err := agentTenantStore.GetTenant(ctx, store.GetTenantQuery{
			ID: tenantID,
		})
		require.NoError(t, err)
		assert.Equal(t, tenantName, aTenantRes.Tenant.Name, "tenant name should match in agent db")
		assert.Equal(t, tenantID, aTenantRes.Tenant.ID, "tenant ID should match in agent db")
	})

	t.Run("should announce multiple keys and complete jobs", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-cli-test-" + uuid.New().String(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		tenantName := tenantResp.GetTenant().GetName()

		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")

		homeDir := t.TempDir()
		// login with no auth
		loginNoAuth(t, homeDir)

		seedSelectedTenant(t, homeDir, tenantID, tenantName)

		k2Name := "cli-key-" + uuid.New().String()
		cmd := newCLICommand(ctx, homeDir, "announce", "key",
			"--kind", "K2",
			"--name", k2Name,
			"--parent", parentID,
			"--target-name", "agent-k1",
			"--label", "cloud=aws",
			"--json",
			"--server", "localhost:"+env.RootPort,
		)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))

		rows := decodeAnnouncedKey(t, output)
		require.Len(t, rows, 1)
		k2key := rows[0]

		assert.Equal(t, "K2", k2key.Kind)
		assert.Equal(t, k2Name, k2key.Name)
		assert.Equal(t, parentID, k2key.ParentID)
		assert.Equal(t, "agent-k1", k2key.ManagedBy)
		assert.Equal(t, "pending", k2key.Status)
		assert.NotEmpty(t, k2key.ID)

		awaitKeyExists(t, env.AgentDB, k2key.ID, tenantID, 10*time.Second)
		awaitJobStatus(t, env.RootDB, k2Name, "DONE", 15*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, k2key.ID, tenantID, "completed", 15*time.Second)

		k3Name := "cli-key-" + uuid.New().String()
		cmd = newCLICommand(ctx, homeDir, "announce", "key",
			"--kind", "K3",
			"--name", k3Name,
			"--parent", k2key.ID,
			"--target-name", "agent-k1",
			"--label", "cloud=aws",
			"--json",
			"--server", "localhost:"+env.RootPort,
		)
		output, err = cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))

		rows = decodeAnnouncedKey(t, output)
		require.Len(t, rows, 1)
		k3key := rows[0]

		assert.Equal(t, "K3", k3key.Kind)
		assert.Equal(t, k3Name, k3key.Name)
		assert.Equal(t, k2key.ID, k3key.ParentID)
		assert.Equal(t, "agent-k1", k3key.ManagedBy)
		assert.Equal(t, "pending", k3key.Status)
		assert.NotEmpty(t, k3key.ID)

		awaitKeyExists(t, env.AgentDB, k3key.ID, tenantID, 10*time.Second)
		awaitJobStatus(t, env.RootDB, k3Name, "DONE", 15*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, k3key.ID, tenantID, "completed", 15*time.Second)
	})
}

type announcedKeyRow struct {
	ID        string
	Kind      string
	Name      string
	ParentID  string
	ManagedBy string
	Labels    map[string]string
	Status    string
	JobID     string
}

func decodeAnnouncedKey(t *testing.T, output []byte) []announcedKeyRow {
	t.Helper()
	var rows []announcedKeyRow
	if err := json.Unmarshal(output, &rows); err != nil {
		assert.FailNowf(t, "failed to decode response", "output: %s, error: %v", string(output), err)
	}
	return rows
}
