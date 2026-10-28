package activatekey_test

import (
	"database/sql"
	"encoding/json/v2"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/handler/activatekey"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestActivate_Handler(t *testing.T) {
	rootName := "test-root"
	rootDB := newRootDB(t)
	kStore := storesql.NewKeyStore(rootDB)
	kvStore := storesql.NewKeyVersionStore(rootDB)
	tenant := createTenant(t, rootDB)

	ctx := t.Context()

	validHierarchy := spec.KeyHierarchy{
		Name: "production-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
		},
	}
	validRootCfg := &config.RootConfig{Hierarchy: validHierarchy}

	mgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
		KeyStore:        kStore,
		KeyVersionStore: kvStore,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			"K0": {SealerSpec: newTestSealerSpec(t), CryptorSpec: newTestCryptorSpec(), VaultSpec: newTestVaultSpec()},
			"K1": {SealerSpec: newTestSealerSpec(t), CryptorSpec: newTestCryptorSpec(), VaultSpec: newTestVaultSpec()},
		},
		Hierarchy: validHierarchy,
	})
	require.NoError(t, err)

	// default handler: root-managed, with empty registry
	subj := activatekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		emptyRegistry(t),
		rootName,
		mgr,
		validRootCfg,
	)

	// newHandler builds a TaskHandler with the given overrides.
	newHandler := func(transactor store.Transactor, registry *grpcconn.Registry, manager *keyprocessor.Manager) *activatekey.TaskHandler {
		if transactor == nil {
			transactor = storesql.NewTransactor(rootDB)
		}
		if manager == nil {
			manager = mgr
		}
		return activatekey.NewTaskHandler(transactor, registry, rootName, manager, validRootCfg)
	}

	// ---- input validation ----

	t.Run("should fail if task data is invalid JSON", func(t *testing.T) {
		// when
		resp := runTask(t, subj, []byte("not-valid-json"))

		// then
		assertTaskFailed(t, resp)
		assert.Zero(t, resp.ReconcileAfterSec)
	})

	// ---- tenant validation ----

	t.Run("should retry if tenant fetching fails", func(t *testing.T) {
		// given
		tmpDB := newRootDB(t)
		tmpStore := storesql.NewKeyStore(tmpDB)
		tmpTenant := createTenant(t, tmpDB)
		key := createKey(t, tmpStore, model.Key{
			TenantID: tmpTenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		renameTenantTable(t, tmpDB)

		// when
		resp := runTask(t, newHandler(storesql.NewTransactor(tmpDB), nil, nil), taskDataForKey(t, key))

		// then
		assertTaskRetry(t, resp)
	})

	t.Run("should fail if tenant is not found", func(t *testing.T) {
		// given
		tmpDB := newRootDB(t)
		tmpStore := storesql.NewKeyStore(tmpDB)
		tmpTenant := createTenant(t, tmpDB)
		key := createKey(t, tmpStore, model.Key{
			TenantID: tmpTenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		taskdata := jsonMarshal(t, handler.KeyIdentifier{ID: key.ID, TenantID: uuid.New().String()})

		// when
		resp := runTask(t, newHandler(storesql.NewTransactor(tmpDB), nil, nil), taskdata)

		// then
		assertTaskFailed(t, resp)
	})

	// ---- key state guards ----

	t.Run("should skip if key is not in active state", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleDeactivated,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		resp := runTask(t, subj, taskDataForKey(t, key))

		// then
		assertTaskDone(t, resp)
	})

	t.Run("should skip if key is not in pending status", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingFailed},
		})

		// when
		resp := runTask(t, subj, taskDataForKey(t, key))

		// then
		assertTaskDone(t, resp)
	})

	// ---- fetchKey ----

	t.Run("should fail if key is not found", func(t *testing.T) {
		// given
		taskdata := jsonMarshal(t, handler.KeyIdentifier{ID: uuid.New().String(), TenantID: tenant.ID})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assertTaskFailed(t, resp)
	})

	t.Run("should retry if fetchKey returns an internal error", func(t *testing.T) {
		// given
		taskdata := jsonMarshal(t, handler.KeyIdentifier{ID: "non-uuid", TenantID: tenant.ID})

		// when
		resp := runTask(t, subj, taskdata)

		// then
		assertTaskRetry(t, resp)
	})

	// ---- upsertAndResolveKeyVersion ----

	t.Run("should fail if parent key version is not found", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleDeactivated // not active, so child won't find a usable parent
		})
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		resp := runTask(t, subj, taskDataForKey(t, key1))

		// then
		assertTaskFailed(t, resp)
		assertKeyState(t, kStore, key1.ID, key1.TenantID, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- generateAndSealSecret ----

	t.Run("should fail if key kind is not in hierarchy", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0-wrong", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		resp := runTask(t, subj, taskDataForKey(t, key))

		// then
		assertTaskFailed(t, resp)
		assertKeyState(t, kStore, key.ID, key.TenantID, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should retry if secret generation fails", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(pc.key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		incompleteMgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore: kStore, KeyVersionStore: kvStore,
			Bindings:  map[model.KeyKind]spec.KeyBinding{"K0": {SealerSpec: newTestSealerSpec(t), CryptorSpec: newTestCryptorSpec(), VaultSpec: newTestVaultSpec()}},
			Hierarchy: validHierarchy,
		})
		require.NoError(t, err)

		// when
		resp := runTask(t, newHandler(nil, nil, incompleteMgr), taskDataForKey(t, key1))

		// then
		assertTaskRetry(t, resp)
	})

	// ---- upsertRemote: registry errors ----

	t.Run("should fail if registry is nil", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key2 := createRemoteKey(t, kStore, tenant.ID, pc.key1.ID, "agent-1")

		// when
		resp := runTask(t, newHandler(nil, nil, nil), taskDataForKey(t, key2))

		// then
		assertTaskFailed(t, resp)
		assertKeyState(t, kStore, key2.ID, key2.TenantID, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail if agent is not in registry", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key2 := createRemoteKey(t, kStore, tenant.ID, pc.key1.ID, "agent-1")

		// when
		resp := runTask(t, newHandler(nil, emptyRegistry(t), nil), taskDataForKey(t, key2))

		// then
		assertTaskFailed(t, resp)
		assertKeyState(t, kStore, key2.ID, key2.TenantID, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- upsertRemoteKey ----

	t.Run("should retry if upsertRemoteKey returns a retryable error", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key2 := createRemoteKey(t, kStore, tenant.ID, pc.key1.ID, "agent-1")
		agentSrv := startAgentServer(t, nil)
		dropTenantTable(t, agentSrv.db) // generic DB error -> ERROR_CODE_RETRY

		// when
		resp := runTask(t, newHandler(nil, newRegistry(t, "agent-1", agentSrv), nil), taskDataForKey(t, key2))

		// then
		assertTaskRetry(t, resp)
		assertKeyState(t, kStore, key2.ID, key2.TenantID, model.KeyProcessingPending, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if upsertRemoteKey returns a non-retryable error", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key2 := createRemoteKey(t, kStore, tenant.ID, pc.key1.ID, "agent-1")
		agentSrv := startAgentServer(t, nil) // no tenant seeded -> ErrTenantNotFound -> ERROR_CODE_ABORT

		// when
		resp := runTask(t, newHandler(nil, newRegistry(t, "agent-1", agentSrv), nil), taskDataForKey(t, key2))

		// then
		assertTaskFailed(t, resp)
		assertKeyState(t, kStore, key2.ID, key2.TenantID, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- upsertRemoteKeyVersion ----

	t.Run("should retry if upsertRemoteKeyVersion returns a retryable error", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key2 := createRemoteKey(t, kStore, tenant.ID, pc.key1.ID, "agent-1")
		agentSrv := startAgentServer(t, nil)
		seedAgentTenant(t, agentSrv.db, tenant.ID)
		dropKeyVersionsTable(t, agentSrv.db) // upsertRemoteKey succeeds, key_versions missing -> ERROR_CODE_RETRY

		// when
		resp := runTask(t, newHandler(nil, newRegistry(t, "agent-1", agentSrv), nil), taskDataForKey(t, key2))

		// then
		assertTaskRetry(t, resp)
		assertKeyState(t, kStore, key2.ID, key2.TenantID, model.KeyProcessingPending, model.KeyLifeCycleActive)
	})

	// ---- happy path: root-managed keys ----

	t.Run("should activate root key and create key version", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		resp := runTask(t, subj, taskDataForKey(t, key0))

		// then
		assertTaskDone(t, resp)
		assertKeyState(t, kStore, key0.ID, key0.TenantID, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
		assertKeyVersionCreated(t, kvStore, key0.TenantID, key0.ID)
	})

	t.Run("should activate non-root key and create key version from parent", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(pc.key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// when
		resp := runTask(t, subj, taskDataForKey(t, key1))

		// then
		assertTaskDone(t, resp)
		assertKeyState(t, kStore, key1.ID, key1.TenantID, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
		kv := assertKeyVersionCreated(t, kvStore, key1.TenantID, key1.ID)
		assert.Equal(t, pc.kv0.Version, *kv.ParentKeyVersion)
	})

	t.Run("should activate non-root key and update existing key version", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(pc.key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		kv1 := createKeyVersion(t, kvStore, tenant.ID, key1.ID, 100, &pc.key0.ID, &pc.kv0.Version, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleSuspended
		})

		// when
		resp := runTask(t, subj, taskDataForKey(t, key1))

		// then
		assertTaskDone(t, resp)
		kv := assertKeyVersionCreated(t, kvStore, key1.TenantID, key1.ID)
		assert.Equal(t, kv1.Version, kv.Version)
		assert.Equal(t, pc.kv0.Version, *kv.ParentKeyVersion)
	})

	// ---- happy path: remote-managed key with RPC sealer ----

	t.Run("should activate remote-managed key with RPC sealer", func(t *testing.T) {
		// given
		pc := createParentChain(t, kStore, kvStore, tenant.ID, rootName)
		key2 := createRemoteKey(t, kStore, tenant.ID, pc.key1.ID, "agent-1")

		rootSealerSrv := startAgentServerFromDB(t, newAgentDB(t), nil, newTestSealer(t))

		agentDB := newAgentDB(t)
		agentMgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore: storesql.NewKeyStore(agentDB), KeyVersionStore: storesql.NewKeyVersionStore(agentDB),
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K2": {
					SealerSpec: newTestSealerSpec(t), CryptorSpec: newTestCryptorSpec(), VaultSpec: newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: "root"},
				},
			},
			Hierarchy: validHierarchy,
			Registry:  newRegistry(t, "root", rootSealerSrv),
		})
		require.NoError(t, err)

		agentSrv := startAgentServerFromDB(t, agentDB, agentMgr, nil)
		seedAgentTenant(t, agentSrv.db, tenant.ID)

		// when
		resp := runTask(t, newHandler(nil, newRegistry(t, "agent-1", agentSrv), nil), taskDataForKey(t, key2))

		// then
		assertTaskDone(t, resp)

		assertKeyState(t, kStore, key2.ID, key2.TenantID, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
		rootKV := assertKeyVersionCreated(t, kvStore, key2.TenantID, key2.ID)

		agentKey, err := agentSrv.keyStore.GetKeyByID(ctx, key2.ID, key2.TenantID)
		require.NoError(t, err)
		assert.Equal(t, key2.Kind, agentKey.Kind)
		assert.Equal(t, model.KeyLifeCycleActive, agentKey.LifeCycleState)

		agentKV := assertKeyVersionCreated(t, agentSrv.kvStore, key2.TenantID, key2.ID)
		assert.Equal(t, rootKV.Version, agentKV.Version)
	})
}

func jsonMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

func renameTenantTable(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(t.Context(), "ALTER TABLE tenants RENAME TO tenants_hidden")
	require.NoError(t, err)
}

func createKeyVersion(
	t *testing.T,
	db store.KeyVersion,
	tenantID, keyID string,
	version int,
	parentID *string,
	parentKeyVersion *int,
	opts ...func(*model.KeyVersion),
) model.KeyVersion {
	t.Helper()
	kv := model.NewKeyVersion(tenantID, keyID, version, parentID, parentKeyVersion)
	for _, opt := range opts {
		opt(&kv)
	}
	res, err := db.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
	require.NoError(t, err)
	return res.KeyVersion
}
