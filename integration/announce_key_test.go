package integration

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
)

func TestAnnounceKey(t *testing.T) {
	env := setupEnvironment(t)

	tenantCli := admin.NewTenantServiceClient(env.Conn)
	keyCli := admin.NewKeyServiceClient(env.Conn)

	t.Run("should announce key to agent and complete job", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-test-" + uuid.NewString(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		tenantName := tenantResp.GetTenant().GetName()

		insertTenant(t, env.AgentDB, tenantID, tenantName)

		keyName := "test-key-" + uuid.NewString()
		resp, err := keyCli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			TargetName: "agent-k1",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)

		keyID := resp.GetKey().GetId()
		assert.Equal(t, "pre-activation", resp.GetKey().GetState())
		assert.Equal(t, "agent-k1", resp.GetKey().GetManagedBy())

		awaitJobStatus(t, env.RootDB, keyID, "DONE", 30*time.Second)
		awaitKeyExists(t, env.AgentDB, keyID, tenantID, 10*time.Second)
	})

	t.Run("should mark key as announce-failed when agent fails", func(t *testing.T) {
		ctx := t.Context()

		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-fail-test-" + uuid.NewString(),
		})
		require.NoError(t, err)

		tenantID := tenantResp.GetTenant().GetId()
		// Intentionally NOT inserting tenant in agent DB
		// → agent's CreateKey fails with FK violation → resp.Fail() → job FAILED

		keyName := "test-key-fail-" + uuid.NewString()
		resp, err := keyCli.AnnounceKey(ctx, &admin.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName,
			TargetName: "agent-k1",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)

		keyID := resp.GetKey().GetId()
		assert.Equal(t, "pre-activation", resp.GetKey().GetState())

		awaitJobStatus(t, env.RootDB, keyID, "FAILED", 60*time.Second)
		awaitKeyState(t, env.RootDB, keyID, tenantID, "announce-failed", 30*time.Second)
	})
}
