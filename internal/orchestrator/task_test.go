package orchestrator_test

import (
	"database/sql"
	"encoding/json/v2"
	"fmt"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/grpcconn"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/orchestrator"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func Test_CommonHandlerSubtests(
	t *testing.T,
) {
	tts := []struct {
		name       string
		handlerCfg orchestrator.HandlerConfig
	}{
		{name: "activate", handlerCfg: orchestrator.ActivateHandlerConfig()},
		{name: "suspend", handlerCfg: orchestrator.SuspendHandlerConfig()},
		{name: "compromise", handlerCfg: orchestrator.CompromiseHandlerConfig()},
		{name: "deactivate", handlerCfg: orchestrator.DeactivateHandlerConfig()},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			env := newTaskTestEnv(t)
			cfg := tt.handlerCfg
			subj := env.handler(t, cfg)
			targetState := orchestrator.ToHandlerState(cfg)
			wrongState := model.KeyLifeCyclePreActivation

			// ---- input validation ----

			t.Run("should fail if task data is invalid JSON", func(t *testing.T) {
				resp := runTask(t, subj, []byte("not-valid-json"))

				assertTaskFailed(t, resp)
				assert.Zero(t, resp.ReconcileAfterSec)
			})

			// ---- tenant validation ----

			t.Run("should retry if tenant fetching fails", func(t *testing.T) {
				tmpDB := newRootDB(t)
				tmpStore := storesql.NewKeyStore(tmpDB)
				tmpTenant := createTenant(t, tmpDB)
				key := createKey(t, tmpStore, model.Key{
					TenantID:           tmpTenant.ID,
					Kind:               "K0",
					ManagedBy:          rootName,
					LifeCycleState:     targetState,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
				})
				renameTenantTable(t, tmpDB)

				resp := runTask(t,
					env.handlerWith(cfg, storesql.NewTransactor(tmpDB), nil, nil),
					taskDataForKey(t, key),
				)

				assertTaskRetry(t, resp)
			})

			t.Run("should fail if tenant is not found", func(t *testing.T) {
				tmpDB := newRootDB(t)
				tmpStore := storesql.NewKeyStore(tmpDB)
				tmpTenant := createTenant(t, tmpDB)
				key := createKey(t, tmpStore, model.Key{
					TenantID:           tmpTenant.ID,
					Kind:               "K0",
					ManagedBy:          rootName,
					LifeCycleState:     targetState,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
				})
				taskdata := jsonMarshal(t, orchestrator.KeyIdentifier{
					ID:       key.ID,
					TenantID: uuid.New().String(),
				})

				resp := runTask(t,
					env.handlerWith(cfg, storesql.NewTransactor(tmpDB), nil, nil),
					taskdata,
				)

				assertTaskFailed(t, resp)
			})

			// ---- key state guards ----

			t.Run("should skip if key lifecycle state does not match", func(t *testing.T) {
				key := createKey(t, env.rootKs, model.Key{
					TenantID:           env.tenant.ID,
					Kind:               "K0",
					ManagedBy:          rootName,
					LifeCycleState:     wrongState,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
				})

				resp := runTask(t, subj, taskDataForKey(t, key))

				assertTaskDone(t, resp)
			})

			t.Run("should skip if key is not in pending status", func(t *testing.T) {
				key := createKey(t, env.rootKs, model.Key{
					TenantID:           env.tenant.ID,
					Kind:               "K0",
					ManagedBy:          rootName,
					LifeCycleState:     targetState,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingFailed},
				})

				resp := runTask(t, subj, taskDataForKey(t, key))

				assertTaskDone(t, resp)
			})

			// ---- fetchKey ----

			t.Run("should fail if key is not found", func(t *testing.T) {
				taskdata := jsonMarshal(t, orchestrator.KeyIdentifier{
					ID:       uuid.New().String(),
					TenantID: env.tenant.ID,
				})

				resp := runTask(t, subj, taskdata)

				assertTaskFailed(t, resp)
			})

			t.Run("should retry if fetchKey returns an internal error", func(t *testing.T) {
				taskdata := jsonMarshal(t, orchestrator.KeyIdentifier{
					ID:       "non-uuid",
					TenantID: env.tenant.ID,
				})

				resp := runTask(t, subj, taskdata)

				assertTaskRetry(t, resp)
			})

			// ---- upsertRemote: registry errors ----

			t.Run("should fail if registry is nil", func(t *testing.T) {
				pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
				key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", targetState)

				resp := runTask(t,
					env.handlerWith(cfg, nil, nil, nil),
					taskDataForKey(t, key2),
				)

				assertTaskFailed(t, resp)
				assertKeyState(t, env.rootKs, key2, model.KeyProcessingFailed, targetState)
			})

			t.Run("should fail if agent is not in registry", func(t *testing.T) {
				pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
				key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", targetState)

				resp := runTask(t,
					env.handlerWith(cfg, nil, emptyRegistry(t), nil),
					taskDataForKey(t, key2),
				)

				assertTaskFailed(t, resp)
				assertKeyState(t, env.rootKs, key2, model.KeyProcessingFailed, targetState)
			})

			// ---- upsertRemoteKey ----

			t.Run("should retry if upsertRemoteKey returns a retryable error", func(t *testing.T) {
				pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
				key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", targetState)
				agentSrv := startAgentServer(t, nil)
				dropTenantTable(t, agentSrv.db) // generic DB error -> ERROR_CODE_RETRY

				resp := runTask(t,
					env.handlerWith(cfg, nil, newRegistry(t, "agent-1", agentSrv), nil),
					taskDataForKey(t, key2),
				)

				assertTaskRetry(t, resp)
				assertKeyState(t, env.rootKs, key2, model.KeyProcessingPending, targetState)
			})

			t.Run("should fail key if upsertRemoteKey returns a non-retryable error", func(t *testing.T) {
				pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
				key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", targetState)
				agentSrv := startAgentServer(t, nil) // no tenant seeded -> ErrTenantNotFound -> ERROR_CODE_ABORT

				resp := runTask(t,
					env.handlerWith(cfg, nil, newRegistry(t, "agent-1", agentSrv), nil),
					taskDataForKey(t, key2),
				)

				assertTaskFailed(t, resp)
				assertKeyState(t, env.rootKs, key2, model.KeyProcessingFailed, targetState)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// TestActivate_Handler
// ---------------------------------------------------------------------------

func TestActivate_Handler(t *testing.T) {
	env := newTaskTestEnv(t)
	cfg := orchestrator.ActivateHandlerConfig()
	subj := env.handler(t, cfg)

	// ---- upsertAndResolveKeyVersion ----

	t.Run("should fail if parent key version is not found", func(t *testing.T) {
		key0 := createKey(t, env.rootKs, model.Key{
			TenantID:           env.tenant.ID,
			Kind:               "K0",
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		createKeyVersion(t, env.rootKvs, env.tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleDeactivated // not active, so child won't find a usable parent
		})
		key1 := createKey(t, env.rootKs, model.Key{
			TenantID:           env.tenant.ID,
			Kind:               "K1",
			ParentID:           new(key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		resp := runTask(t, subj, taskDataForKey(t, key1))

		assertTaskFailed(t, resp)
		assertKeyState(t, env.rootKs, key1, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- generateAndSealSecret ----

	t.Run("should fail if key kind is not in hierarchy", func(t *testing.T) {
		key := createKey(t, env.rootKs, model.Key{
			TenantID:           env.tenant.ID,
			Kind:               "K0-wrong",
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		resp := runTask(t, subj, taskDataForKey(t, key))

		assertTaskFailed(t, resp)
		assertKeyState(t, env.rootKs, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should retry if secret generation fails", func(t *testing.T) {
		pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
		key1 := createKey(t, env.rootKs, model.Key{
			TenantID:           env.tenant.ID,
			Kind:               "K1",
			ParentID:           new(pc.key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		// Manager with only K0 binding -- K1 generation will fail.
		incompleteMgr, err := keyprocessor.NewManager(t.Context(), keyprocessor.ManagerConfig{
			KeyStore:        env.rootKs,
			KeyVersionStore: env.rootKvs,
			Bindings:        map[model.KeyKind]spec.KeyBinding{"K0": newTestBinding(t)},
			Hierarchy:       env.hierarchy,
		})
		require.NoError(t, err)

		resp := runTask(t,
			env.handlerWith(cfg, nil, nil, incompleteMgr),
			taskDataForKey(t, key1),
		)

		assertTaskRetry(t, resp)
	})

	// ---- upsertRemoteKeyVersion ----

	t.Run("should retry if upsertRemoteKeyVersion returns a retryable error", func(t *testing.T) {
		pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
		key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", model.KeyLifeCycleActive)

		agentSrv := startAgentServer(t, nil)
		seedAgentTenant(t, agentSrv.db, env.tenant.ID)
		dropKeyVersionsTable(t, agentSrv.db) // upsertRemoteKey succeeds, key_versions missing -> ERROR_CODE_RETRY

		resp := runTask(t,
			env.handlerWith(cfg, nil, newRegistry(t, "agent-1", agentSrv), nil),
			taskDataForKey(t, key2),
		)

		assertTaskRetry(t, resp)
		assertKeyState(t, env.rootKs, key2, model.KeyProcessingPending, model.KeyLifeCycleActive)
	})

	// ---- happy path: root-managed keys ----

	t.Run("should activate root key and create key version", func(t *testing.T) {
		key0 := createKey(t, env.rootKs, model.Key{
			TenantID:           env.tenant.ID,
			Kind:               "K0",
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		resp := runTask(t, subj, taskDataForKey(t, key0))

		assertTaskDone(t, resp)
		assertKeyState(t, env.rootKs, key0, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
		assertKeyVersionCreated(t, env.rootKvs, key0.TenantID, key0.ID)
	})

	t.Run("should activate non-root key and create key version from parent", func(t *testing.T) {
		pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
		key1 := createKey(t, env.rootKs, model.Key{
			TenantID:           env.tenant.ID,
			Kind:               "K1",
			ParentID:           new(pc.key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		resp := runTask(t, subj, taskDataForKey(t, key1))

		assertTaskDone(t, resp)
		assertKeyState(t, env.rootKs, key1, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
		kv := assertKeyVersionCreated(t, env.rootKvs, key1.TenantID, key1.ID)
		assert.Equal(t, pc.kv0.Version, *kv.ParentKeyVersion)
	})

	t.Run("should activate non-root key and update existing key version", func(t *testing.T) {
		pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
		key1 := createKey(t, env.rootKs, model.Key{
			TenantID:           env.tenant.ID,
			Kind:               "K1",
			ParentID:           new(pc.key0.ID),
			ManagedBy:          rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		kv1 := createKeyVersion(t, env.rootKvs, env.tenant.ID, key1.ID, 100,
			&pc.key0.ID, &pc.kv0.Version,
			func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionUsable
				kv.LifeCycleState = model.KeyLifeCycleSuspended
			},
		)

		resp := runTask(t, subj, taskDataForKey(t, key1))

		assertTaskDone(t, resp)
		kv := assertKeyVersionCreated(t, env.rootKvs, key1.TenantID, key1.ID)
		assert.Equal(t, kv1.Version, kv.Version)
		assert.Equal(t, pc.kv0.Version, *kv.ParentKeyVersion)
	})

	// ---- happy path: remote-managed key with RPC sealer ----

	t.Run("should activate remote-managed key with RPC sealer", func(t *testing.T) {
		pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
		key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", model.KeyLifeCycleActive)

		agentSrv, _ := startRemoteAgent(t, env, "root")
		seedAgentTenant(t, agentSrv.db, env.tenant.ID)

		resp := runTask(t,
			env.handlerWith(cfg, nil, newRegistry(t, "agent-1", agentSrv), nil),
			taskDataForKey(t, key2),
		)

		assertTaskDone(t, resp)
		assertKeyState(t, env.rootKs, key2, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
		rootKV := assertKeyVersionCreated(t, env.rootKvs, key2.TenantID, key2.ID)

		assertKeyState(t, agentSrv.keyStore, key2, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
		agentKV := assertKeyVersionCreated(t, agentSrv.kvStore, key2.TenantID, key2.ID)
		assert.Equal(t, rootKV.Version, agentKV.Version)
	})

	t.Run("should re-activate remote-managed key when key already exists on agent", func(t *testing.T) {
		pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
		key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", model.KeyLifeCycleActive)

		agentSrv, agentStores := startRemoteAgent(t, env, "root")
		seedAgentTenant(t, agentSrv.db, env.tenant.ID)

		// Pre-seed key and key version on agent (simulates a previous activation).
		existingAgentKey := model.NewKey(key2.TenantID, key2.Name, string(key2.Kind), key2.ParentID, key2.ManagedBy, nil)
		existingAgentKey.ID = key2.ID
		existingAgentKey.LifeCycleState = model.KeyLifeCycleSuspended
		existingAgentKey.KeyProcessingState = model.KeyProcessingState{Status: model.KeyProcessingCompleted}
		require.NoError(t, agentStores.keyStore.CreateKey(t.Context(), existingAgentKey))

		createKeyVersion(t, agentStores.kvStore, key2.TenantID, key2.ID, 1,
			&pc.key1.ID, &pc.kv1.Version,
			func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionReWrapping
				kv.LifeCycleState = model.KeyLifeCycleSuspended
			},
		)

		resp := runTask(t,
			env.handlerWith(cfg, nil, newRegistry(t, "agent-1", agentSrv), nil),
			taskDataForKey(t, key2),
		)

		assertTaskDone(t, resp)
		assertKeyState(t, env.rootKs, key2, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
		rootKV := assertKeyVersionCreated(t, env.rootKvs, key2.TenantID, key2.ID)

		// Verify agent DB: key updated to active.
		assertKeyState(t, agentSrv.keyStore, key2, model.KeyProcessingCompleted, model.KeyLifeCycleActive)

		// Verify agent DB: key version updated.
		agentKV := assertKeyVersionCreated(t, agentSrv.kvStore, key2.TenantID, key2.ID)
		assert.Equal(t, rootKV.Version, agentKV.Version)
		assert.Equal(t, model.KeyVersionUsable, agentKV.ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, agentKV.LifeCycleState)
	})
}

// ---------------------------------------------------------------------------
// TestCommon_Handlers (suspend, compromise, deactivate)
// ---------------------------------------------------------------------------

func TestCommon_Handlers(t *testing.T) {
	tts := []struct {
		name       string
		handlerCfg orchestrator.HandlerConfig
	}{
		{name: "suspend", handlerCfg: orchestrator.SuspendHandlerConfig()},
		{name: "compromise", handlerCfg: orchestrator.CompromiseHandlerConfig()},
		{name: "deactivate", handlerCfg: orchestrator.DeactivateHandlerConfig()},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			env := newTaskTestEnv(t)
			cfg := tt.handlerCfg
			toState := orchestrator.ToHandlerState(cfg)
			subj := env.handler(t, cfg)

			// ---- happy path: root-managed keys ----

			t.Run(fmt.Sprintf("should %s root key", tt.name), func(t *testing.T) {
				key0 := createKey(t, env.rootKs, model.Key{
					TenantID:           env.tenant.ID,
					Kind:               "K0",
					ManagedBy:          rootName,
					LifeCycleState:     toState,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
				})

				resp := runTask(t, subj, taskDataForKey(t, key0))

				assertTaskDone(t, resp)
				assertKeyState(t, env.rootKs, key0, model.KeyProcessingCompleted, toState)
			})

			t.Run(fmt.Sprintf("should %s non-root key", tt.name), func(t *testing.T) {
				pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
				key1 := createKey(t, env.rootKs, model.Key{
					TenantID:           env.tenant.ID,
					Kind:               "K1",
					ParentID:           new(pc.key0.ID),
					ManagedBy:          rootName,
					LifeCycleState:     toState,
					KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
				})

				resp := runTask(t, subj, taskDataForKey(t, key1))

				assertTaskDone(t, resp)
				assertKeyState(t, env.rootKs, key1, model.KeyProcessingCompleted, toState)
			})

			// ---- happy path: remote-managed key with RPC sealer ----

			t.Run(fmt.Sprintf("should %s remote-managed key with RPC sealer", tt.name), func(t *testing.T) {
				pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
				key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", toState)

				agentSrv, _ := startRemoteAgent(t, env, "root")
				seedAgentTenant(t, agentSrv.db, env.tenant.ID)

				resp := runTask(t,
					env.handlerWith(cfg, nil, newRegistry(t, "agent-1", agentSrv), nil),
					taskDataForKey(t, key2),
				)

				assertTaskDone(t, resp)
				assertKeyState(t, env.rootKs, key2, model.KeyProcessingCompleted, toState)
				assertKeyState(t, agentSrv.keyStore, key2, model.KeyProcessingCompleted, toState)
			})

			t.Run(fmt.Sprintf("should %s remote-managed key when key already exists on agent", tt.name), func(t *testing.T) {
				pc := createParentChain(t, env.rootMgr, env.rootKs, env.rootKvs, env.tenant.ID, rootName)
				key2 := createKeyWithState(t, env.rootKs, env.tenant.ID, pc.key1.ID, "agent-1", toState)

				agentSrv, agentStores := startRemoteAgent(t, env, "root")
				seedAgentTenant(t, agentSrv.db, env.tenant.ID)

				existingAgentKey := model.NewKey(key2.TenantID, key2.Name, string(key2.Kind), key2.ParentID, key2.ManagedBy, nil)
				existingAgentKey.ID = key2.ID
				existingAgentKey.LifeCycleState = model.KeyLifeCyclePreActivation
				existingAgentKey.KeyProcessingState = model.KeyProcessingState{Status: model.KeyProcessingCompleted}
				require.NoError(t, agentStores.keyStore.CreateKey(t.Context(), existingAgentKey))

				resp := runTask(t,
					env.handlerWith(cfg, nil, newRegistry(t, "agent-1", agentSrv), nil),
					taskDataForKey(t, key2),
				)

				assertTaskDone(t, resp)
				assertKeyState(t, env.rootKs, key2, model.KeyProcessingCompleted, toState)
				assertKeyState(t, agentSrv.keyStore, key2, model.KeyProcessingCompleted, toState)
			})
		})
	}
}

// ---------------------------------------------------------------------------
// Shared test environment
// ---------------------------------------------------------------------------

// taskTestEnv bundles the common infrastructure every task handler test needs:
// a database, stores, a tenant, the key hierarchy, and a fully wired manager.
type taskTestEnv struct {
	rootDB    *sql.DB
	rootKs    store.Key
	rootKvs   store.KeyVersion
	tenant    model.Tenant
	hierarchy spec.KeyHierarchy
	rootCfg   *config.RootConfig
	rootMgr   *keyprocessor.RootManager
	mgr       *keyprocessor.Manager
}

// ---------------------------------------------------------------------------
// Remote agent helpers
// ---------------------------------------------------------------------------

// agentStores gives direct access to the agent-side stores used during a test.
type agentStores struct {
	keyStore store.Key
	kvStore  store.KeyVersion
}

func newTaskTestEnv(t *testing.T) *taskTestEnv {
	t.Helper()

	db := newRootDB(t)
	ks := storesql.NewKeyStore(db)
	kvs := storesql.NewKeyVersionStore(db)
	tenant := createTenant(t, db)

	hierarchy := spec.KeyHierarchy{
		Name: "production-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
		},
	}

	rootMgr := newTestRootManager(t, db)

	mgr, err := keyprocessor.NewManager(t.Context(), keyprocessor.ManagerConfig{
		KeyStore:        ks,
		KeyVersionStore: kvs,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			"K0": newTestBinding(t),
			"K1": newTestBinding(t),
		},
		Hierarchy:   hierarchy,
		RootManager: rootMgr,
	})
	require.NoError(t, err)

	return &taskTestEnv{
		rootDB:    db,
		rootKs:    ks,
		rootKvs:   kvs,
		tenant:    tenant,
		hierarchy: hierarchy,
		rootCfg: &config.RootConfig{
			Name:      rootName,
			Hierarchy: hierarchy,
		},
		rootMgr: rootMgr,
		mgr:     mgr,
	}
}

// handler returns the default TaskHandler backed by the env's stores, an empty
// registry, and the env's key-processor manager.
func (e *taskTestEnv) handler(t *testing.T, cfg orchestrator.HandlerConfig) *orchestrator.TaskHandler {
	t.Helper()
	return orchestrator.NewTaskHandler(
		cfg, storesql.NewTransactor(e.rootDB), emptyRegistry(t), e.mgr, e.rootCfg,
	)
}

// handlerWith builds a TaskHandler, applying non-nil overrides on top of the
// env defaults (nil transactor -> env DB, nil manager -> env manager).
func (e *taskTestEnv) handlerWith(
	cfg orchestrator.HandlerConfig,
	transactor store.Transactor,
	registry *grpcconn.Registry,
	manager *keyprocessor.Manager,
) *orchestrator.TaskHandler {
	if transactor == nil {
		transactor = storesql.NewTransactor(e.rootDB)
	}
	if manager == nil {
		manager = e.mgr
	}
	return orchestrator.NewTaskHandler(cfg, transactor, registry, manager, e.rootCfg)
}

// startRemoteAgent spins up a gRPC agent server whose K2 key binding uses an
// RPC sealer backed by rootSealerName. It returns the running server and the
// underlying agent-side stores for assertion purposes.
func startRemoteAgent(t *testing.T, env *taskTestEnv, rootSealerName string) (*agentServer, agentStores) {
	t.Helper()

	rootSealerSrv := startAgentServerFromDB(t, newAgentDB(t), nil, newTestSealer(t))

	agentDB := newAgentDB(t)
	agentKeyStore := storesql.NewKeyStore(agentDB)
	agentKVStore := storesql.NewKeyVersionStore(agentDB)

	agentMgr, err := keyprocessor.NewManager(t.Context(), keyprocessor.ManagerConfig{
		KeyStore:        agentKeyStore,
		KeyVersionStore: agentKVStore,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			"K2": {
				SealerSpec:        newTestSealerSpec(t),
				CryptorSpec:       newTestCryptorSpec(),
				VaultSpec:         newTestVaultSpec(),
				ParentKeyProvider: &spec.ParentKeyProviderRef{AgentName: rootSealerName},
			},
		},
		Hierarchy: env.hierarchy,
		Registry:  newRegistry(t, rootSealerName, rootSealerSrv),
	})
	require.NoError(t, err)

	srv := startAgentServerFromDB(t, agentDB, agentMgr, nil)
	return srv, agentStores{keyStore: agentKeyStore, kvStore: agentKVStore}
}

// ---------------------------------------------------------------------------
// Helpers local to this file
// ---------------------------------------------------------------------------

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
