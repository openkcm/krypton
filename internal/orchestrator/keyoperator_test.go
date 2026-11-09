package orchestrator_test

import (
	"context"
	"errors"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
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

func TestNewKeyOperator(t *testing.T) {
	db := newRootDB(t)
	kStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)
	stores := store.Stores{Keys: kStore, KeyVersions: kvStore, Tenants: storesql.NewTenantStore(db)}

	cfg := &config.RootConfig{
		Name: "test-root",
		Hierarchy: spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			},
		},
	}

	t.Run("should create processor with zero-valued outputs", func(t *testing.T) {
		// when
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})

		// then
		require.NotNil(t, p)
		assert.Nil(t, p.Key)
		assert.Nil(t, p.KeyVersion)
		assert.False(t, p.IsNewKV)
	})
}

func TestLoadKey(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)
	stores := store.Stores{Keys: kStore, KeyVersions: kvStore, Tenants: storesql.NewTenantStore(db)}

	rootName := "test-root"
	cfg := &config.RootConfig{
		Name: rootName,
		Hierarchy: spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			},
		},
	}

	t.Run("should return error if KID is nil", func(t *testing.T) {
		// given
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
				KID:        nil,
			})

		// when
		or := p.LoadKey(t.Context())

		// then
		assert.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
	})

	t.Run("should return OrbitalFail when key is not found", func(t *testing.T) {
		// given
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager: nil, RootConfig: cfg, Registry: nil, Stores: stores,
				KID: &orchestrator.KeyIdentifier{ID: uuid.New().String(), TenantID: tenant.ID},
			})

		// when
		or := p.LoadKey(t.Context())

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
	})

	t.Run("should retry when LoadKey returns an internal DB error", func(t *testing.T) {
		// given — "non-uuid" triggers a SQL error (not ErrKeyNotFound)
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager: nil, RootConfig: cfg, Registry: nil, Stores: stores,
				KID: &orchestrator.KeyIdentifier{ID: "non-uuid", TenantID: tenant.ID},
			})

		// when
		or := p.LoadKey(t.Context())

		// then
		require.NotNil(t, or)
		resp := applyResponse(t, or)
		assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
		assert.Positive(t, resp.ReconcileAfterSec)
	})
}

func TestResolveKeyVersions(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)
	stores := store.Stores{Keys: kStore, KeyVersions: kvStore, Tenants: storesql.NewTenantStore(db)}

	rootName := "test-root"
	cfg := &config.RootConfig{
		Name: rootName,
		Hierarchy: spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			},
		},
	}

	t.Run("should return error if key is nil", func(t *testing.T) {
		// given
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
				KID:        nil,
			})

		// when
		or := p.ResolveKeyVersions(t.Context())

		// then
		assert.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
	})

	t.Run("should create new key version for root key", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
				KID:        &orchestrator.KeyIdentifier{ID: key.ID, TenantID: tenant.ID},
			})
		ctx := t.Context()

		// when
		or := p.LoadKey(ctx)
		assert.Nil(t, or)
		or = p.ResolveKeyVersions(ctx)

		// then
		assert.Nil(t, or)
		require.NotNil(t, p.Key)
		assert.Equal(t, key.ID, p.Key.ID)
		require.NotNil(t, p.KeyVersion)
		assert.Equal(t, model.KeyVersionUsable, p.KeyVersion.ProcessingState)
		assert.True(t, p.IsNewKV)
	})

	t.Run("should update existing key version", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		createKeyVersion(t, kvStore, tenant.ID, key.ID, 1, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionReWrapping
			kv.LifeCycleState = model.KeyLifeCycleSuspended
		})
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
				KID:        &orchestrator.KeyIdentifier{ID: key.ID, TenantID: tenant.ID},
			})

		ctx := t.Context()

		// when
		or := p.LoadKey(ctx)
		assert.Nil(t, or)
		or = p.ResolveKeyVersions(ctx)

		// then
		assert.Nil(t, or)
		require.NotNil(t, p.KeyVersion)
		assert.Equal(t, model.KeyVersionUsable, p.KeyVersion.ProcessingState)
		assert.False(t, p.IsNewKV)
	})

	t.Run("should fail key when parent key version is not found", func(t *testing.T) {
		// given
		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleDeactivated
		})
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
				KID:        &orchestrator.KeyIdentifier{ID: key1.ID, TenantID: tenant.ID},
			})

		ctx := t.Context()

		// when
		or := p.LoadKey(ctx)
		assert.Nil(t, or)
		or = p.ResolveKeyVersions(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key1, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})
}

func TestGenerateAndSealLocalSecret(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)
	stores := store.Stores{Keys: kStore, KeyVersions: kvStore, Tenants: storesql.NewTenantStore(db)}

	ctx := t.Context()
	rootName := "test-root"
	hierarchy := spec.KeyHierarchy{
		Name: "test-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
			{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
		},
	}
	cfg := &config.RootConfig{
		Name:      rootName,
		Hierarchy: hierarchy,
	}

	rootMgr := newTestRootManager(t, db)

	mgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
		KeyStore: kStore, KeyVersionStore: kvStore,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			"K0": newTestBinding(t),
			"K1": newTestBinding(t),
		},
		Hierarchy:   hierarchy,
		RootManager: rootMgr,
	})
	require.NoError(t, err)

	// mgrNoK2 has no binding for K2 — if GenerateAndSealSecret reaches the
	// manager call for a K2 key, it will fail, proving the skip didn't work.
	mgrNoK2, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
		KeyStore: kStore, KeyVersionStore: kvStore,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			"K0": newTestBinding(t),
			"K1": newTestBinding(t),
		},
		Hierarchy:   hierarchy,
		RootManager: rootMgr,
	})
	require.NoError(t, err)

	// helper: create a processor with key and key version loaded
	loadProcessor := func(t *testing.T, manager *keyprocessor.Manager, key model.Key) *orchestrator.KeyOperator {
		t.Helper()
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    manager,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
				KID:        &orchestrator.KeyIdentifier{ID: key.ID, TenantID: key.TenantID},
			})
		// when
		or := p.LoadKey(ctx)
		assert.Nil(t, or)
		or = p.ResolveKeyVersions(ctx)
		require.Nil(t, or)
		return p
	}

	t.Run("should skip generation if key is not managed by root", func(t *testing.T) {
		// given — K2 managed by agent, manager has no K2 binding
		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})
		key2 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K2", ParentID: new(key0.ID), ManagedBy: "agent-1",
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := loadProcessor(t, mgrNoK2, key2)
		require.True(t, p.IsNewKV) // new KV, but should still skip

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then — nil means generation was skipped (manager would fail for K2)
		assert.Nil(t, or)
	})

	t.Run("should skip generation if key is a root key", func(t *testing.T) {
		// given — K0 is root role, managed by root, new KV
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := loadProcessor(t, mgrNoK2, key)
		require.True(t, p.IsNewKV)

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		assert.Nil(t, or)
	})

	t.Run("should skip generation if key version is not new", func(t *testing.T) {
		// given — K1 managed by root, but existing KV (IsNewKV=false)
		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		kv0 := createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		createKeyVersion(t, kvStore, tenant.ID, key1.ID, 1, &key0.ID, &kv0.Version, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleSuspended
		})
		// use mgrNoK2 (has K1 binding but we rely on IsNewKV=false to skip)
		p := loadProcessor(t, mgrNoK2, key1)
		require.False(t, p.IsNewKV)

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		assert.Nil(t, or)
	})

	t.Run("should generate and seal secret for new non-root key managed by root", func(t *testing.T) {
		// given — provision the root key (K0) through the RootManager so that a
		// provider spec is stored and version 1 carries the provider-key label.
		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCyclePreActivation,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		require.NoError(t, rootMgr.CreateProvider(ctx, keyprocessor.CreateProviderInput{
			TenantID:      tenant.ID,
			KeyID:         key0.ID,
			Spec:          newInlineStaticSecretSpec(t),
			ProviderKeyID: "pk-1",
		}))
		activateRootKey(t, kStore, key0)

		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := loadProcessor(t, mgr, key1)
		require.True(t, p.IsNewKV) // new KV created from parent

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		assert.Nil(t, or)
	})

	t.Run("should retry if secret generation fails", func(t *testing.T) {
		// given — manager without K1 binding
		incompleteMgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore: kStore, KeyVersionStore: kvStore,
			Bindings:  map[model.KeyKind]spec.KeyBinding{"K0": newTestBinding(t)},
			Hierarchy: hierarchy,
		})
		require.NoError(t, err)

		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := loadProcessor(t, incompleteMgr, key1)
		require.True(t, p.IsNewKV)

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusProcessing), applyResponse(t, or).Status)
	})

	t.Run("should fail if key kind is not in hierarchy", func(t *testing.T) {
		// given — key with unknown kind
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K-unknown", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := loadProcessor(t, mgr, key)

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if config is nil", func(t *testing.T) {
		// given — nil config causes isRootKey to fail
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		kv := model.NewKeyVersion(tenant.ID, key.ID, 1, nil, nil)
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    mgr,
				RootConfig: nil, // nil config
				Registry:   nil,
				Stores:     stores,
			})
		p.Key = &key
		p.KeyVersion = &kv
		p.IsNewKV = true

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- nil/empty guards ----

	t.Run("should fail if key is nil", func(t *testing.T) {
		// given
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    mgr,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})
		// Key is nil (LoadKeyAndVersions not called)

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
	})

	t.Run("should fail key if key version is nil", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    mgr,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})
		p.Key = &key // set key but leave KeyVersion nil

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if manager is nil", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		kv := model.NewKeyVersion(tenant.ID, key.ID, 1, nil, nil)
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil, // nil manager
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})
		p.Key = &key
		p.KeyVersion = &kv

		// when
		or := p.GenerateAndSealLocalSecret(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})
}

func TestMarkKeyFailed(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	stores := store.Stores{Keys: kStore, KeyVersions: storesql.NewKeyVersionStore(db), Tenants: storesql.NewTenantStore(db)}

	rootName := "test-root"
	cfg := &config.RootConfig{}

	t.Run("should return OrbitalFail when key is nil", func(t *testing.T) {
		// given
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})
		// Key is nil (LoadKeyAndVersions not called)

		// when
		or := p.MarkKeyFailed(t.Context(), errors.New("something went wrong"))

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
	})

	t.Run("should update key processing state to failed and return OrbitalFail", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})
		p.Key = &key

		// when
		or := p.MarkKeyFailed(t.Context(), errors.New("seal failed"))

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should return OrbitalContinue when DB update fails", func(t *testing.T) {
		// given
		brokenDB := newRootDB(t)
		brokenTenant := createTenant(t, brokenDB)
		brokenKStore := storesql.NewKeyStore(brokenDB)
		key := createKey(t, brokenKStore, model.Key{
			TenantID: brokenTenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		_, err := brokenDB.ExecContext(t.Context(), "ALTER TABLE keys RENAME TO keys_hidden")
		require.NoError(t, err)

		brokenStores := store.Stores{Keys: brokenKStore}
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     brokenStores,
			})
		p.Key = &key

		// when
		or := p.MarkKeyFailed(t.Context(), errors.New("original error"))

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusProcessing), applyResponse(t, or).Status)
	})
}

func TestUpsertRemoteKey(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)
	stores := store.Stores{Keys: kStore, KeyVersions: kvStore, Tenants: storesql.NewTenantStore(db)}

	ctx := t.Context()
	rootName := "test-root"
	cfg := &config.RootConfig{
		Name: rootName,
		Hierarchy: spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
			},
		},
	}

	// helper: create K0 -> K1 parent chain with key versions, then K2 managed by agent
	createRemoteKeyHierarchy := func(t *testing.T) model.Key {
		t.Helper()
		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		kv0 := createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		createKeyVersion(t, kvStore, tenant.ID, key1.ID, 100, &key0.ID, &kv0.Version, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})
		return createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K2", ParentID: new(key1.ID), ManagedBy: "agent-1",
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
	}

	// helper: load processor with key and key version
	loadProcessor := func(t *testing.T, key model.Key, registry *grpcconn.Registry) *orchestrator.KeyOperator {
		t.Helper()
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   registry,
				Stores:     stores,
				KID:        &orchestrator.KeyIdentifier{ID: key.ID, TenantID: key.TenantID},
			})
		or := p.LoadKey(ctx)
		assert.Nil(t, or)
		or = p.ResolveKeyVersions(ctx)
		require.Nil(t, or)
		return p
	}

	// ---- skip ----

	t.Run("should skip if key is managed by root", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := loadProcessor(t, key, emptyRegistry(t))

		// when
		or := p.UpsertRemoteKey(ctx)

		// then
		assert.Nil(t, or)
	})

	// ---- nil/empty guards ----

	t.Run("should fail if key is nil", func(t *testing.T) {
		// given
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   emptyRegistry(t),
				Stores:     stores,
			})

		// when
		or := p.UpsertRemoteKey(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
	})

	t.Run("should fail key if registry is nil", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		p := loadProcessor(t, key, emptyRegistry(t))
		// loadProcessor used emptyRegistry but we need nil registry on the processor;
		// we can't set it directly (unexported), so create a fresh processor with nil registry
		p2 := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})
		p2.Key = p.Key

		// when
		or := p2.UpsertRemoteKey(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if root config is nil", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		p := loadProcessor(t, key, emptyRegistry(t))
		// loadProcessor used emptyRegistry but we need nil registry on the processor;
		// we can't set it directly (unexported), so create a fresh processor with nil registry
		p2 := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: nil,
				Registry:   emptyRegistry(t),
				Stores:     stores,
			})
		p2.Key = p.Key

		// when
		or := p2.UpsertRemoteKey(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if root name is empty", func(t *testing.T) {
		// given — empty root name means no key is considered "managed by root",
		// so the agent-managed key proceeds to registry lookup and fails.
		key := createRemoteKeyHierarchy(t)
		p := loadProcessor(t, key, emptyRegistry(t))
		p2 := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: &config.RootConfig{Name: "", Hierarchy: cfg.Hierarchy},
				Registry:   emptyRegistry(t),
				Stores:     stores,
			})
		p2.Key = p.Key

		// when
		or := p2.UpsertRemoteKey(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- agent not found ----

	t.Run("should fail key if agent is not in registry", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		p := loadProcessor(t, key, emptyRegistry(t))

		// when
		or := p.UpsertRemoteKey(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- upsertRemoteKey ----

	t.Run("should retry if grpc returns a retryable error", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		agentSrv := startAgentServer(t, nil)
		dropTenantTable(t, agentSrv.db) // generic DB error -> ERROR_CODE_RETRY
		p := loadProcessor(t, key, newRegistry(t, "agent-1", agentSrv))

		// when
		or := p.UpsertRemoteKey(ctx)

		// then
		require.NotNil(t, or)
		resp := applyResponse(t, or)
		assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
		assert.Positive(t, resp.ReconcileAfterSec)
		assertKeyState(t, kStore, key, model.KeyProcessingPending, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if grpc returns a non-retryable error", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		agentSrv := startAgentServer(t, nil) // no tenant seeded -> ErrTenantNotFound -> ERROR_CODE_ABORT
		p := loadProcessor(t, key, newRegistry(t, "agent-1", agentSrv))

		// when
		or := p.UpsertRemoteKey(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- happy path ----

	t.Run("should upsert key to agent", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		agentSrv := startAgentServer(t, nil)
		seedAgentTenant(t, agentSrv.db, tenant.ID)

		// pre-seed key and KV in agent DB so UpsertKeyVersion takes the update
		// path (skips generateAndSealSecret which needs a non-nil manager)
		p := loadProcessor(t, key, newRegistry(t, "agent-1", agentSrv))
		agentKey := *p.Key
		agentKey.KeyProcessingState = model.KeyProcessingState{Status: model.KeyProcessingCompleted}
		require.NoError(t, agentSrv.keyStore.CreateKey(ctx, agentKey))
		createKeyVersion(t, agentSrv.kvStore, key.TenantID, key.ID, p.KeyVersion.Version,
			p.KeyVersion.ParentKeyID, p.KeyVersion.ParentKeyVersion, func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionReWrapping
				kv.LifeCycleState = model.KeyLifeCycleSuspended
			})

		// when
		or := p.UpsertRemoteKey(ctx)

		// then
		assert.Nil(t, or)

		// verify agent DB: key upserted
		assertKeyState(t, agentSrv.keyStore, key, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
	})
}

func TestUpsertRemoteKeyVersion(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	kvStore := storesql.NewKeyVersionStore(db)
	stores := store.Stores{Keys: kStore, KeyVersions: kvStore, Tenants: storesql.NewTenantStore(db)}

	ctx := t.Context()
	rootName := "test-root"
	cfg := &config.RootConfig{
		Name: rootName,
		Hierarchy: spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
			},
		},
	}

	// helper: create K0 -> K1 parent chain with key versions, then K2 managed by agent
	createRemoteKeyHierarchy := func(t *testing.T) model.Key {
		t.Helper()
		key0 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		kv0 := createKeyVersion(t, kvStore, tenant.ID, key0.ID, 100, nil, nil, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})
		key1 := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K1", ParentID: new(key0.ID), ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		})
		createKeyVersion(t, kvStore, tenant.ID, key1.ID, 100, &key0.ID, &kv0.Version, func(kv *model.KeyVersion) {
			kv.ProcessingState = model.KeyVersionUsable
			kv.LifeCycleState = model.KeyLifeCycleActive
		})
		return createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K2", ParentID: new(key1.ID), ManagedBy: "agent-1",
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
	}

	// helper: load processor with key and key version
	loadProcessor := func(t *testing.T, key model.Key, registry *grpcconn.Registry) *orchestrator.KeyOperator {
		t.Helper()
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   registry,
				Stores:     stores,
				KID:        &orchestrator.KeyIdentifier{ID: key.ID, TenantID: key.TenantID},
			})
		or := p.LoadKey(ctx)
		assert.Nil(t, or)
		or = p.ResolveKeyVersions(ctx)
		require.Nil(t, or)
		return p
	}

	// ---- skip ----

	t.Run("should skip if key is managed by root", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := loadProcessor(t, key, emptyRegistry(t))

		// when
		or := p.UpsertRemoteKeyVersion(ctx)

		// then
		assert.Nil(t, or)
	})

	// ---- nil/empty guards ----

	t.Run("should fail if key is nil", func(t *testing.T) {
		// given
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   emptyRegistry(t),
				Stores:     stores,
			})
		p.Key = nil

		// when
		or := p.UpsertRemoteKeyVersion(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
	})

	t.Run("should fail key if key version is nil", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   emptyRegistry(t),
				Stores:     stores,
			})
		p.Key = &key

		// when
		or := p.UpsertRemoteKeyVersion(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if registry is nil", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		p := loadProcessor(t, key, emptyRegistry(t))
		// loadProcessor used emptyRegistry but we need nil registry on the processor;
		// we can't set it directly (unexported), so create a fresh processor with nil registry
		p2 := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})
		p2.Key = p.Key
		p2.KeyVersion = p.KeyVersion

		// when
		or := p2.UpsertRemoteKeyVersion(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if root config is nil", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		p := loadProcessor(t, key, emptyRegistry(t))
		// loadProcessor used emptyRegistry but we need nil registry on the processor;
		// we can't set it directly (unexported), so create a fresh processor with nil registry
		p2 := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: nil,
				Registry:   emptyRegistry(t),
				Stores:     stores,
			})
		p2.Key = p.Key
		p2.KeyVersion = p.KeyVersion

		// when
		or := p2.UpsertRemoteKeyVersion(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if root name is empty", func(t *testing.T) {
		// given — empty root name means no key is considered "managed by root",
		// so the agent-managed key proceeds to registry lookup and fails.
		key := createRemoteKeyHierarchy(t)
		p := loadProcessor(t, key, emptyRegistry(t))
		p2 := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: &config.RootConfig{Name: "", Hierarchy: cfg.Hierarchy},
				Registry:   emptyRegistry(t),
				Stores:     stores,
			})
		p2.Key = p.Key
		p2.KeyVersion = p.KeyVersion

		// when
		or := p2.UpsertRemoteKeyVersion(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- agent not found ----

	t.Run("should fail key if agent is not in registry", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		p := loadProcessor(t, key, emptyRegistry(t))

		// when
		or := p.UpsertRemoteKeyVersion(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	t.Run("should fail key if grpc returns a non-retryable error", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		agentSrv := startAgentServer(t, nil) // no tenant seeded -> ErrTenantNotFound -> ERROR_CODE_ABORT
		p := loadProcessor(t, key, newRegistry(t, "agent-1", agentSrv))

		// when
		or := p.UpsertRemoteKeyVersion(ctx)

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
		assertKeyState(t, kStore, key, model.KeyProcessingFailed, model.KeyLifeCycleActive)
	})

	// ---- upsertRemoteKeyVersion ----

	t.Run("should retry if grpc returns a retryable error", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		agentSrv := startAgentServer(t, nil)
		dropTenantTable(t, agentSrv.db) // generic DB error -> ERROR_CODE_RETRY
		p := loadProcessor(t, key, newRegistry(t, "agent-1", agentSrv))

		// when
		or := p.UpsertRemoteKeyVersion(ctx)

		// then
		require.NotNil(t, or)
		resp := applyResponse(t, or)
		assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
		assert.Positive(t, resp.ReconcileAfterSec)
		assertKeyState(t, kStore, key, model.KeyProcessingPending, model.KeyLifeCycleActive)
	})

	// ---- happy path ----

	t.Run("should upsert key version to agent", func(t *testing.T) {
		// given
		key := createRemoteKeyHierarchy(t)
		agentSrv := startAgentServer(t, nil)
		seedAgentTenant(t, agentSrv.db, tenant.ID)

		// pre-seed key and KV in agent DB so UpsertKeyVersion takes the update
		// path (skips generateAndSealSecret which needs a non-nil manager)
		p := loadProcessor(t, key, newRegistry(t, "agent-1", agentSrv))
		agentKey := *p.Key
		agentKey.KeyProcessingState = model.KeyProcessingState{Status: model.KeyProcessingCompleted}
		require.NoError(t, agentSrv.keyStore.CreateKey(ctx, agentKey))
		createKeyVersion(t, agentSrv.kvStore, key.TenantID, key.ID, p.KeyVersion.Version,
			p.KeyVersion.ParentKeyID, p.KeyVersion.ParentKeyVersion, func(kv *model.KeyVersion) {
				kv.ProcessingState = model.KeyVersionReWrapping
				kv.LifeCycleState = model.KeyLifeCycleSuspended
			})

		// when
		or := p.UpsertRemoteKeyVersion(ctx)

		// then
		assert.Nil(t, or)

		// verify agent DB: key version updated
		agentKVs, err := agentSrv.kvStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: key.TenantID, KeyID: key.ID,
		})
		require.NoError(t, err)
		require.Len(t, agentKVs.KeyVersions, 1)
		assert.Equal(t, p.KeyVersion.Version, agentKVs.KeyVersions[0].Version)
		assert.Equal(t, p.KeyVersion.Revision, agentKVs.KeyVersions[0].Revision)
		assert.Equal(t, model.KeyVersionUsable, agentKVs.KeyVersions[0].ProcessingState)
		assert.Equal(t, model.KeyLifeCycleActive, agentKVs.KeyVersions[0].LifeCycleState)
	})
}

func TestMarkKeyCompleted(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	kStore := storesql.NewKeyStore(db)
	stores := store.Stores{Keys: kStore, KeyVersions: storesql.NewKeyVersionStore(db), Tenants: storesql.NewTenantStore(db)}

	rootName := "test-root"
	cfg := &config.RootConfig{}

	t.Run("should return OrbitalFail when key is nil", func(t *testing.T) {
		// given
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})

		// when
		or := p.MarkKeyCompleted(t.Context())

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusFailed), applyResponse(t, or).Status)
	})

	t.Run("should mark key as completed", func(t *testing.T) {
		// given
		key := createKey(t, kStore, model.Key{
			TenantID: tenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})
		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager:    nil,
				RootConfig: cfg,
				Registry:   nil,
				Stores:     stores,
			})
		p.Key = &key

		// when
		or := p.MarkKeyCompleted(t.Context())

		// then
		assert.Nil(t, or)
		assertKeyState(t, kStore, key, model.KeyProcessingCompleted, model.KeyLifeCycleActive)
	})

	t.Run("should return OrbitalContinue when DB update fails", func(t *testing.T) {
		// given
		brokenDB := newRootDB(t)
		brokenTenant := createTenant(t, brokenDB)
		brokenKStore := storesql.NewKeyStore(brokenDB)
		key := createKey(t, brokenKStore, model.Key{
			TenantID: brokenTenant.ID, Kind: "K0", ManagedBy: rootName,
			LifeCycleState:     model.KeyLifeCycleActive,
			KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
		})

		_, err := brokenDB.ExecContext(t.Context(), "ALTER TABLE keys RENAME TO keys_hidden")
		require.NoError(t, err)

		p := orchestrator.NewKeyOperator(
			orchestrator.KeyOperatorConfig{
				Manager: nil, RootConfig: cfg, Registry: nil, Stores: store.Stores{Keys: brokenKStore},
			})
		p.Key = &key

		// when
		or := p.MarkKeyCompleted(t.Context())

		// then
		require.NotNil(t, or)
		assert.Equal(t, string(orbital.TaskStatusProcessing), applyResponse(t, or).Status)
	})
}

func TestExecuteKeyOperator(t *testing.T) {
	p := orchestrator.NewKeyOperator(orchestrator.KeyOperatorConfig{})

	// helper: run Execute inside an orbital handler and return the task response.
	executeWith := func(t *testing.T, pipeline orchestrator.OperatorPipelineFunc) (orbital.TaskResponse, error) {
		t.Helper()
		var execErr error
		resp := orbital.ExecuteHandler(t.Context(), orbital.HandlerFunc(
			func(ctx context.Context, _ orbital.HandlerRequest, r *orbital.HandlerResponse) {
				execErr = p.Execute(ctx, pipeline, r)
			},
		), orbital.TaskRequest{TaskID: uuid.New(), Type: "test"})
		return resp, execErr
	}

	t.Run("should complete when all steps succeed", func(t *testing.T) {
		// given
		var called []int
		pipeline := func(_ *orchestrator.KeyOperator) []orchestrator.OperatorStepFunc {
			return []orchestrator.OperatorStepFunc{
				func(_ context.Context) *orchestrator.OrbitalOperatorError { called = append(called, 1); return nil },
				func(_ context.Context) *orchestrator.OrbitalOperatorError { called = append(called, 2); return nil },
				func(_ context.Context) *orchestrator.OrbitalOperatorError { called = append(called, 3); return nil },
			}
		}

		// when
		resp, err := executeWith(t, pipeline)

		// then
		require.NoError(t, err)
		assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)
		assert.Equal(t, []int{1, 2, 3}, called)
	})

	t.Run("should fail when pipelineFunc is nil", func(t *testing.T) {
		// given
		// when
		resp, err := executeWith(t, nil)

		// then
		require.NoError(t, err)
		assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	})

	t.Run("should complete with empty pipeline", func(t *testing.T) {
		// given
		pipeline := func(_ *orchestrator.KeyOperator) []orchestrator.OperatorStepFunc {
			return nil
		}

		// when
		resp, err := executeWith(t, pipeline)

		// then
		require.NoError(t, err)
		assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)
	})

	t.Run("should fail when first step returns OrbitalFail", func(t *testing.T) {
		// given
		var called []int
		pipeline := func(_ *orchestrator.KeyOperator) []orchestrator.OperatorStepFunc {
			return []orchestrator.OperatorStepFunc{
				func(_ context.Context) *orchestrator.OrbitalOperatorError {
					called = append(called, 1)
					return orchestrator.OrbitalFail(errors.New("step 1 failed"))
				},
				func(_ context.Context) *orchestrator.OrbitalOperatorError { called = append(called, 2); return nil },
			}
		}

		// when
		resp, err := executeWith(t, pipeline)

		// then
		require.NoError(t, err) // OrbitalFail applies to resp, returns nil
		assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
		assert.Equal(t, []int{1}, called, "second step should not run")
	})

	t.Run("should retry when middle step returns OrbitalContinue", func(t *testing.T) {
		// given
		var called []int
		pipeline := func(_ *orchestrator.KeyOperator) []orchestrator.OperatorStepFunc {
			return []orchestrator.OperatorStepFunc{
				func(_ context.Context) *orchestrator.OrbitalOperatorError { called = append(called, 1); return nil },
				func(_ context.Context) *orchestrator.OrbitalOperatorError {
					called = append(called, 2)
					return orchestrator.OrbitalContinue(errors.New("transient"))
				},
				func(_ context.Context) *orchestrator.OrbitalOperatorError { called = append(called, 3); return nil },
			}
		}

		// when
		resp, err := executeWith(t, pipeline)

		// then
		require.Error(t, err) // OrbitalContinue propagates the error
		assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
		assert.Positive(t, resp.ReconcileAfterSec)
		assert.Equal(t, []int{1, 2}, called, "third step should not run")
	})
}
