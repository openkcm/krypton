package integration

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type activatedKeyRow struct {
	Status bool
}

func TestActivateKey(t *testing.T) {
	env := setupEnvironment(t)
	rootKVStore := newKeyVersionStore(t, env.RootDB)
	rootKStore := newKeyStore(t, env.RootDB)

	tenantCli := admin.NewTenantServiceClient(env.Conn)
	keyCli := keypb.NewKeyServiceClient(env.Conn)

	ctx := t.Context()

	t.Run("should activate root key", func(t *testing.T) {
		// given
		// Create a tenant
		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-root-test-" + uuid.NewString(),
		})
		require.NoError(t, err)
		tenantID := tenantResp.GetTenant().GetId()

		// announce key root key
		resp, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		keyID := resp.GetKey().GetId()

		// when
		cmd := newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", keyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err := cmd.CombinedOutput()

		// then
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// checking key status
		key, err := rootKStore.GetKeyByID(ctx, keyID, tenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, key.KeyProcessingState.Status)

		// check key version status
		kvr, err := rootKVStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    keyID,
			OrderBy: []store.KeyVersionOrder{
				store.KeyVersionOrderVersionDesc,
				store.KeyVersionOrderRevisionDesc,
			},
		})
		require.NoError(t, err)
		assert.Len(t, kvr.KeyVersions, 1, "there should be exactly one key version after activation")
		kv := kvr.KeyVersions[0]
		assert.Equal(t, model.KeyLifeCycleActive, kv.LifeCycleState)
		assert.Equal(t, model.KeyVersionUsable, kv.ProcessingState)
	})

	t.Run("should activate intermediate key", func(t *testing.T) {
		// given
		// Create a tenant
		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-root-test-" + uuid.NewString(),
		})
		require.NoError(t, err)
		tenantID := tenantResp.GetTenant().GetId()

		// announce key root key
		resp, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		keyID := resp.GetKey().GetId()

		// activate root key
		cmd := newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", keyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// announce intermediate key
		resp, err = keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K1",
			Name:       "k1-key-" + uuid.NewString(),
			TargetName: "",
			ParentId:   keyID,
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		keyID = resp.GetKey().GetId()

		// when
		// activate intermediate key
		cmd = newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", keyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err = cmd.CombinedOutput()

		// then
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// checking key status
		key, err := rootKStore.GetKeyByID(ctx, keyID, tenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, key.KeyProcessingState.Status)

		// check key version status
		kvr, err := rootKVStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    keyID,
			OrderBy: []store.KeyVersionOrder{
				store.KeyVersionOrderVersionDesc,
				store.KeyVersionOrderRevisionDesc,
			},
		})
		require.NoError(t, err)
		assert.Len(t, kvr.KeyVersions, 1, "there should be exactly one key version after activation")
		kv := kvr.KeyVersions[0]
		assert.Equal(t, model.KeyLifeCycleActive, kv.LifeCycleState)
		assert.Equal(t, model.KeyVersionUsable, kv.ProcessingState)
	})

	t.Run("should return error if activate key is called on already activated key", func(t *testing.T) {
		// given
		// Create a tenant
		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-root-test-" + uuid.NewString(),
		})
		require.NoError(t, err)
		tenantID := tenantResp.GetTenant().GetId()

		// announce key root key
		resp, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		keyID := resp.GetKey().GetId()

		// activate root key
		cmd := newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", keyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// when
		// activate root key
		cmd = newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", keyID,
			"--json",
			"--server", "localhost:"+env.RootPort)

		// then
		output, err = cmd.CombinedOutput()
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "failed to activate key")
	})

	t.Run("should return error if activate key is called on non-existent key", func(t *testing.T) {
		// given
		// Create a tenant
		tenantResp, err := tenantCli.CreateTenant(ctx, &admin.CreateTenantRequest{
			Name: "announce-root-test-" + uuid.NewString(),
		})
		require.NoError(t, err)
		tenantID := tenantResp.GetTenant().GetId()

		// when
		cmd := newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", uuid.NewString(),
			"--json",
			"--server", "localhost:"+env.RootPort)

		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "failed to activate key")
	})

	t.Run("should return error", func(t *testing.T) {
		// given
		validUUID := uuid.NewString()
		tts := []struct {
			name string
			args []string
		}{
			{
				name: "if the key ID is not provided",
				args: []string{
					"activate",
					"key",
					"--tenant-id", validUUID,
					"--json",
					"--server", "localhost:" + env.RootPort,
				},
			},
			{
				name: "if the tenant ID is not provided",
				args: []string{
					"activate",
					"key",
					"--key-id", validUUID,
					"--json",
					"--server", "localhost:" + env.RootPort,
				},
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				cmd := newCLICommand(
					t.Context(),
					t.TempDir(),
					tt.args...,
				)

				output, err := cmd.CombinedOutput()

				// then
				assert.Error(t, err, "command should fail, output: %s", string(output))
			})
		}
	})
}

func decodeActivatedKeyRow(t *testing.T, output []byte) activatedKeyRow {
	t.Helper()
	var ar []activatedKeyRow
	err := json.Unmarshal(output, &ar)
	if err != nil {
		assert.FailNowf(t, "failed to decode response", "output: %s, error: %v", string(output), err)
	}
	require.Len(t, ar, 1, "expected exactly one activated key row in the output")
	return ar[0]
}
