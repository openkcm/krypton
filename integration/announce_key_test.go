package integration

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
)

func TestAnnounceKey(t *testing.T) {
	env := setupEnvironment(t)

	tenantCli := admin.NewTenantServiceClient(env.Conn)
	keyCli := keypb.NewKeyServiceClient(env.Conn)

	t.Run("should announce key to agent and complete job", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-test-" + uuid.NewString(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		tenantName := tenantResp.GetTenant().GetName()

		insertTenant(t, env.AgentDB, tenantID, tenantName)
		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")
		insertActiveParentKeyWithID(t, env.AgentDB, tenantID, "K1", parentID)

		keyName := "test-key-" + uuid.NewString()
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
		assert.NotEmpty(t, resp.GetKey().GetKeyProcessingState().GetJobId())

		awaitJobStatus(t, env.RootDB, keyID, "DONE", 30*time.Second)
		awaitKeyExists(t, env.AgentDB, keyID, tenantID, 10*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, keyID, tenantID, "completed", 30*time.Second)
	})

	t.Run("should mark key processing as failed when agent rejects", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-fail-test-" + uuid.NewString(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		// Intentionally NOT inserting tenant in agent DB
		// → agent CreateKey fails with FK violation → resp.Fail() → job FAILED
		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")

		keyName := "test-key-fail-" + uuid.NewString()
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

		awaitJobStatus(t, env.RootDB, keyID, "FAILED", 60*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, keyID, tenantID, "failed", 30*time.Second)
	})

	t.Run("should be idempotent on duplicate (tenant, name)", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "idempotent-test-" + uuid.NewString(),
		})
		require.NoError(t, err)
		tenantID := tenantResp.GetTenant().GetId()
		insertTenant(t, env.AgentDB, tenantID, tenantResp.GetTenant().GetName())
		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")
		insertActiveParentKeyWithID(t, env.AgentDB, tenantID, "K1", parentID)

		keyName := "idempotent-key-" + uuid.NewString()
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
		awaitKeyProcessingStatusViaGRPC(t, keyCli, first.GetKey().GetId(), tenantID, "completed", 30*time.Second)

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

	t.Run("failed retry recovers once agent can accept the key", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-recover-test-" + uuid.NewString(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		tenantName := tenantResp.GetTenant().GetName()
		// First announce: tenant is missing from the agent DB → agent CreateKey
		// hits the tenant FK violation → job FAILED → key processing Failed.
		parentID := insertActiveParentKey(t, env.RootDB, tenantID, "K1")

		keyName := "recover-key-" + uuid.NewString()
		first, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			ParentId:   parentID,
			TargetName: "agent-k1",
		})
		require.NoError(t, err)
		keyID := first.GetKey().GetId()

		awaitJobStatus(t, env.RootDB, keyID, "FAILED", 60*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, keyID, tenantID, "failed", 30*time.Second)

		// Now seed the missing prerequisites on the agent and retry.
		insertTenant(t, env.AgentDB, tenantID, tenantName)
		insertActiveParentKeyWithID(t, env.AgentDB, tenantID, "K1", parentID)

		retry, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			ParentId:   parentID,
			TargetName: "agent-k1",
		})
		require.NoError(t, err)
		assert.Equal(t, keyID, retry.GetKey().GetId(), "retry must reuse the existing key.ID")
		assert.Equal(t, "pending", retry.GetKey().GetKeyProcessingState().GetStatus())

		// The retried job should run to completion and the key end up Completed.
		awaitKeyExists(t, env.AgentDB, keyID, tenantID, 30*time.Second)
		awaitKeyProcessingStatusViaGRPC(t, keyCli, keyID, tenantID, "completed", 60*time.Second)
	})
}
