package integration

import (
	"encoding/json/v2"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ovhkmip "github.com/ovh/kmip-go"

	keypb "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

type activatedKeyRow struct {
	Status     bool
	JobGroupID string
}

func TestActivateKey(t *testing.T) {
	// K0(root) -> K1(kek) -> K2(dek)
	env := setupRootEnvWithKMIP(t)
	rootKVStore := newKeyVersionStore(t, env.RootDB, storesql.Root)
	rootKStore := newKeyStore(t, env.RootDB, storesql.Root)
	tenantID := env.PreConfiguredTenant.ID
	keyCli := keypb.NewKeyServiceClient(env.Conn)

	ctx := t.Context()

	// login with no auth
	homeDir := t.TempDir()
	loginNoAuth(t, homeDir)

	// announceKey announces a key and returns its ID.
	announceKey := func(t *testing.T, kind, name string, parentID string) string {
		t.Helper()
		req := &keypb.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       kind,
			Name:       name + "-" + uuid.New().String(),
			TargetName: "",
			Labels:     map[string]string{"cloud": "aws"},
		}
		if parentID != "" {
			req.ParentId = parentID
		}
		resp, err := keyCli.AnnounceKey(ctx, req)
		require.NoError(t, err)
		return resp.GetKey().GetId()
	}

	// activateKey runs the CLI activate command and asserts it enqueued a group.
	activateKey := func(t *testing.T, keyID string) {
		t.Helper()
		cmd := newCLICommand(
			t.Context(),
			homeDir,
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", keyID,
			"--json",
			"--server", "localhost:"+env.RootPort)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "command should succeed, output: %s", string(output))
		row := decodeActivatedKeyRow(t, output)
		assert.True(t, row.Status)
		assert.NotEmpty(t, row.JobGroupID, "activate should return the enqueued job group ID")
	}

	t.Run("should activate root key (K0)", func(t *testing.T) {
		rootKeyID := announceKey(t, "K0", "root-key", "")
		activateKey(t, rootKeyID)

		// Activation is async: the embedded orchestrator promotes the key.
		kv := waitKeyActive(t, rootKStore, rootKVStore, tenantID, rootKeyID)

		// call KMIP Server to get the key material
		actUID := env.PreConfiguredTenant.ID + ":" + kv.KeyID + ":1"

		// below errors are due to configuration now, but later it should be authorization errors
		_, err := env.PreConfiguredKMIPClient.GetAttributes(actUID).ExecContext(ctx)
		assert.Error(t, err)

		kmipResp, err := env.PreConfiguredKMIPClient.Get(actUID).ExecContext(ctx)
		assert.Error(t, err)
		assert.Nil(t, kmipResp)
	})

	t.Run("should activate intermediate keys (K1)", func(t *testing.T) {
		rootKeyID := announceKey(t, "K0", "root-key", "")
		activateKey(t, rootKeyID)
		// The child announce validates that its parent is active, so wait first.
		waitKeyActive(t, rootKStore, rootKVStore, tenantID, rootKeyID)

		k1KeyID := announceKey(t, "K1", "k1-key", rootKeyID)
		activateKey(t, k1KeyID)
		waitKeyActive(t, rootKStore, rootKVStore, tenantID, k1KeyID)
	})

	t.Run("should activate all keys", func(t *testing.T) {
		rootKeyID := announceKey(t, "K0", "root-key", "")
		activateKey(t, rootKeyID)
		waitKeyActive(t, rootKStore, rootKVStore, tenantID, rootKeyID)

		k1KeyID := announceKey(t, "K1", "k1-key", rootKeyID)
		activateKey(t, k1KeyID)
		waitKeyActive(t, rootKStore, rootKVStore, tenantID, k1KeyID)

		k2KeyID := announceKey(t, "K2", "k2-key", k1KeyID)
		activateKey(t, k2KeyID)
		kv := waitKeyActive(t, rootKStore, rootKVStore, tenantID, k2KeyID)

		assertKMIPGetAttributes(t, env, kv)
		assertKMIPGet(t, env, kv)
	})

	t.Run("re-activating an already active key is an idempotent no-op", func(t *testing.T) {
		keyID := announceKey(t, "K0", "root-key", "")
		activateKey(t, keyID)
		waitKeyActive(t, rootKStore, rootKVStore, tenantID, keyID)

		// A second activation enqueues another group; the task handler
		// short-circuits the already-active key, so the CLI still succeeds and
		// the key keeps exactly one usable version.
		activateKey(t, keyID)
		kv := waitKeyActive(t, rootKStore, rootKVStore, tenantID, keyID)
		assert.Equal(t, 1, kv.Version, "re-activation must not seal a new version")
	})

	t.Run("should return error if activate key is called on non-existent key", func(t *testing.T) {
		cmd := newCLICommand(
			t.Context(),
			homeDir,
			"activate",
			"key",
			"--tenant-id", tenantID,
			"--key-id", uuid.New().String(),
			"--json",
			"--server", "localhost:"+env.RootPort)

		output, err := cmd.CombinedOutput()
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "failed to activate key")
	})

	t.Run("should return error", func(t *testing.T) {
		validUUID := uuid.New().String()
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
				cmd := newCLICommand(
					t.Context(),
					homeDir,
					tt.args...,
				)

				output, err := cmd.CombinedOutput()
				assert.Error(t, err, "command should fail, output: %s", string(output))
			})
		}
	})
}

// waitKeyActive polls root's stores until the key is active with exactly one
// usable, active version, then returns that version. Activation runs
// asynchronously on root's embedded orchestrator, so callers must wait rather
// than read straight through.
func waitKeyActive(t *testing.T, kStore store.Key, kvStore store.KeyVersion, tenantID, keyID string) model.KeyVersion {
	t.Helper()
	ctx := t.Context()

	var usable model.KeyVersion
	require.Eventually(t, func() bool {
		key, err := kStore.GetKeyByID(ctx, keyID, tenantID)
		if err != nil ||
			key.LifeCycleState != model.KeyLifeCycleActive ||
			key.KeyProcessingState.Status != model.KeyProcessingCompleted {
			return false
		}

		kvr, err := kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID:        tenantID,
			KeyID:           keyID,
			ProcessingState: model.KeyVersionUsable,
			LifeCycleState:  model.KeyLifeCycleActive,
			OrderBy: []store.KeyVersionOrder{
				store.KeyVersionOrderVersionDesc,
				store.KeyVersionOrderRevisionDesc,
			},
		})
		if err != nil || len(kvr.KeyVersions) != 1 {
			return false
		}
		usable = kvr.KeyVersions[0]
		return true
	}, 20*time.Second, 200*time.Millisecond, "key %s did not become active", keyID)

	return usable
}

func assertKMIPGetAttributes(t *testing.T, env *testEnvWithRootKMIP, kv model.KeyVersion) {
	t.Helper()

	ctx := t.Context()
	actUID := env.PreConfiguredTenant.ID + ":" + kv.KeyID + ":1"

	resp, err := env.PreConfiguredKMIPClient.GetAttributes(actUID).ExecContext(ctx)
	require.NoError(t, err, "GetAttributes")
	assert.Equal(t, actUID, resp.UniqueIdentifier)
	got := indexAttrs(resp.Attribute)
	assert.Len(t, got, 4)
	assert.Equal(t, ovhkmip.StateActive, got[ovhkmip.AttributeNameState])
	assert.Equal(t, ovhkmip.CryptographicAlgorithmAES, got[ovhkmip.AttributeNameCryptographicAlgorithm])
	assert.Equal(t, int32(256), got[ovhkmip.AttributeNameCryptographicLength])
	assert.Equal(t, ovhkmip.ObjectTypeSymmetricKey, got[ovhkmip.AttributeNameObjectType])
}

func assertKMIPGet(t *testing.T, env *testEnvWithRootKMIP, kv model.KeyVersion) {
	t.Helper()

	ctx := t.Context()
	actUID := env.PreConfiguredTenant.ID + ":" + kv.KeyID + ":1"

	resp, err := env.PreConfiguredKMIPClient.Get(actUID).ExecContext(ctx)
	require.NoError(t, err)
	assert.Equal(t, actUID, resp.UniqueIdentifier)

	sk, ok := resp.Object.(*ovhkmip.SymmetricKey)
	require.True(t, ok, "Object type = %T", resp.Object)

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

func indexAttrs(attrs []ovhkmip.Attribute) map[ovhkmip.AttributeName]any {
	m := make(map[ovhkmip.AttributeName]any, len(attrs))
	for _, a := range attrs {
		m[a.AttributeName] = a.AttributeValue
	}
	return m
}
