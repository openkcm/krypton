package integration

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ovhkmip "github.com/ovh/kmip-go"

	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type activatedKeyRow struct {
	Status bool
}

func TestActivateKey(t *testing.T) {
	// K0(root) -> K1(kek) -> K2(dek)
	env := setupRootEnvWithKMIP(t)
	rootKVStore := newKeyVersionStore(t, env.RootDB)
	rootKStore := newKeyStore(t, env.RootDB)
	tenantID := env.PreConfiguredTenant.ID
	keyCli := keypb.NewKeyServiceClient(env.Conn)

	ctx := t.Context()

	t.Run("should activate root key (K0)", func(t *testing.T) {
		// given
		// announce key root key
		resp, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		rootKeyID := resp.GetKey().GetId()

		// when
		cmd := newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", rootKeyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err := cmd.CombinedOutput()

		// then
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// checking key status
		key, err := rootKStore.GetKeyByID(ctx, rootKeyID, tenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, key.KeyProcessingState.Status)

		// check key version status
		kvr, err := rootKVStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    rootKeyID,
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

		// call KMIP Server to get the key material
		actUID := env.PreConfiguredTenant.ID + ":" + kv.KeyID + ":1"

		kmipResp, err := env.PreConfiguredKMIPClient.Get(actUID).ExecContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, kmipResp)
	})

	t.Run("should activate intermediate keys (K1)", func(t *testing.T) {
		// given
		// announce key root key
		resp, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		rootKeyID := resp.GetKey().GetId()

		// activate root key
		cmd := newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", rootKeyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// announce k1 key
		resp, err = keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K1",
			Name:       "k1-key-" + uuid.NewString(),
			TargetName: "",
			ParentId:   rootKeyID,
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		k1KeyID := resp.GetKey().GetId()

		// when
		// activate k1 key
		cmd = newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", k1KeyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err = cmd.CombinedOutput()

		// then
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// checking key status
		key, err := rootKStore.GetKeyByID(ctx, k1KeyID, tenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, key.KeyProcessingState.Status)

		// check key version status
		kvr, err := rootKVStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    k1KeyID,
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

		assertKMIPKeyRetrievable(t, env, kv)
	})

	t.Run("should activate all keys", func(t *testing.T) {
		// given
		// announce key root key
		resp, err := keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K0",
			Name:       "root-key-" + uuid.NewString(),
			TargetName: "",
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		rootKeyID := resp.GetKey().GetId()

		// activate root key
		cmd := newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", rootKeyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// announce k1 key
		resp, err = keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K1",
			Name:       "k1-key-" + uuid.NewString(),
			TargetName: "",
			ParentId:   rootKeyID,
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		k1KeyID := resp.GetKey().GetId()

		// activate k1 key
		cmd = newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", k1KeyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err = cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// announce k2 key
		resp, err = keyCli.AnnounceKey(ctx, &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       "k2-key-" + uuid.NewString(),
			TargetName: "",
			ParentId:   k1KeyID,
			Labels:     map[string]string{"cloud": "aws"},
		})
		require.NoError(t, err)
		k2KeyID := resp.GetKey().GetId()

		// when
		// activate k2 key
		cmd = newCLICommand(
			t.Context(),
			t.TempDir(),
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", k2KeyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err = cmd.CombinedOutput()

		// then
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		assert.True(t, decodeActivatedKeyRow(t, output).Status)

		// checking key status
		key, err := rootKStore.GetKeyByID(ctx, k2KeyID, tenantID)
		require.NoError(t, err)
		assert.Equal(t, model.KeyLifeCycleActive, key.LifeCycleState)
		assert.Equal(t, model.KeyProcessingCompleted, key.KeyProcessingState.Status)

		// check key version status
		kvr, err := rootKVStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    k2KeyID,
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

		assertKMIPKeyRetrievable(t, env, kv)
	})

	t.Run("should return error if activate key is called on already activated key", func(t *testing.T) {
		// given
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

func assertKMIPKeyRetrievable(t *testing.T, env *testEnvWithRootKMIP, kv model.KeyVersion) {
	t.Helper()

	ctx := t.Context()
	actUID := env.PreConfiguredTenant.ID + ":" + kv.KeyID + ":1"

	kmipResp, err := env.PreConfiguredKMIPClient.Get(actUID).ExecContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, actUID, kmipResp.UniqueIdentifier)

	sk, ok := kmipResp.Object.(*ovhkmip.SymmetricKey)
	require.True(t, ok, "Object type = %T", kmipResp.Object)

	mat, err := sk.KeyMaterial()
	require.NoError(t, err, "KeyMaterial")
	assert.NotNil(t, mat)
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
