package keyprocessor_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestRPCManager(t *testing.T) {
	//	k0 -> k1 -> k2 -> k3
	//	k0 - k1 : managed by the remote "root" agent (mocked via gRPC)
	//	k2 - k3 : managed by the agent
	//
	// K2's parent key provider points to the remote "root" agent, so sealing K2
	// delegates directly to the remote sealer. K3's parent is K2 on the local
	// agent, so sealing K3 is done locally — but requires unsealing K2 first,
	// which triggers a remote unseal since K2's parent is remote.
	t.Run("should seal and unseal secrets across a remote agent", func(t *testing.T) {
		ctx := t.Context()

		// setting up a remote sealer to simulate a parent key provider
		remoteManager := setupRemoteSealer(t, nil)
		rs := remoteManager.mgr
		staticSealer := newTestSealer(t)

		var remoteSealCalled, remoteUnsealCalled int

		rs.fnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			remoteSealCalled++
			return staticSealer.Seal(ctx, req)
		}

		rs.fnUnseal = func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			remoteUnsealCalled++
			return staticSealer.Unseal(ctx, req)
		}

		db := createDatabase(t)
		tenantID := createTenant(t, db)
		kStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		// creating a key processor manager with a remote parent key provider
		mgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore:        kStore,
			KeyVersionStore: kvStore,
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K2": {
					SealerSpec:  newTestSealerSpec(t),
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{
						AgentName: "root",
					},
				},
				"K3": {
					CryptorSpec:       newTestCryptorSpec(),
					VaultSpec:         newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{},
				},
			},
			Hierarchy: spec.KeyHierarchy{
				Name: "production-hierarchy",
				KeySpecs: []spec.KeySpec{
					{
						Kind:      "K0",
						Role:      spec.KeyRoleRoot,
						Algorithm: cryptor.KeyAlgorithmAES256,
					},
					{
						Kind:      "K1",
						Role:      spec.KeyRoleKek,
						Algorithm: cryptor.KeyAlgorithmAES256,
					},
					{
						Kind:      "K2",
						Role:      spec.KeyRoleTek,
						Algorithm: cryptor.KeyAlgorithmAES256,
					},
					{
						Kind:      "K3",
						Role:      spec.KeyRoleDek,
						Algorithm: cryptor.KeyAlgorithmAES256,
					},
				},
			},
			Auth: nil,
			ParentConnection: config.ConnectionConfig{
				Name: "root",
				Address: config.Address{
					Type: config.AddressTypeGRPC,
					URL:  remoteManager.address,
				},
			},
		})
		require.NoError(t, err)

		parentVersion := 1
		aad := []byte("test-aad")

		// seal K2's secret via the local manager (delegates to remote "root")
		k2Key, k2kv := createTestKeyAndVersion(t, kStore, kvStore, tenantID, createKeyAndVersionParams{
			Kind:             "K2",
			ManagedBy:        "agent",
			VersionParentVer: &parentVersion,
		})

		_, err = mgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: k2kv,
			AAD:        aad,
			KeyKind:    k2Key.Kind,
		})
		require.NoError(t, err)

		// sealing K2 delegates to the remote agent (K2's parent is remote "root"),
		// so remote seal is called once; no unseal needed yet
		assert.Equal(t, 1, remoteSealCalled)
		assert.Equal(t, 0, remoteUnsealCalled)

		// seal K3's secret via the local manager (sealed locally using K2)
		k3key, k3kv := createTestKeyAndVersion(t, kStore, kvStore, tenantID, createKeyAndVersionParams{
			Kind:               "K3",
			ManagedBy:          "agent",
			KeyParentID:        &k2Key.ID,
			VersionParentKeyID: &k2Key.ID,
			VersionParentVer:   &k2kv.Version,
		})

		_, err = mgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: k3kv,
			AAD:        aad,
			KeyKind:    k3key.Kind,
		})
		require.NoError(t, err)

		// sealing K3 is handled locally (K3's parent is the local manager),
		// so no additional remote seal is called. However, the local manager must
		// first unseal K2's secret to use it as the encryption key for K3, which
		// triggers one remote unseal (K2's parent is the remote "root" agent).
		assert.Equal(t, 1, remoteSealCalled)
		assert.Equal(t, 1, remoteUnsealCalled)

		res, err := mgr.ExportSecret(ctx, keyprocessor.ExportSecretRequest{
			TenantID:   tenantID,
			KeyID:      k3key.ID,
			KeyVersion: 1,
		})

		require.NoError(t, err)
		assert.NotEmpty(t, res.Data)

		// exporting K3's secret requires unsealing K3, which means unsealing K2
		// again via the remote agent. No additional remote seal is needed.
		assert.Equal(t, 1, remoteSealCalled)
		assert.Equal(t, 2, remoteUnsealCalled)
	})

	// key hierarchy spanning three agents (two agents, one root):
	//
	//	k0 -> k1 -> k2 -> k3 -> k4 -> k5
	//	k0 - k1 : managed by the remote "root" agent (mocked via gRPC)
	//	k2 - k3 : managed by the remote "middle" agent (real Manager + gRPC)
	//	k4 - k5 : managed by the local "leaf" agent (Manager under test)
	//
	// The middle agent connects to root for K2's parent. The leaf agent connects
	// to middle for K4's parent. K3 and K5 are sealed locally by their respective
	// agents, which requires unsealing the parent key up the chain through gRPC.
	t.Run("should seal and unseal secrets across two remote agents", func(t *testing.T) {
		ctx := t.Context()

		// --- root agent (mock gRPC) ---
		rootRemote := setupRemoteSealer(t, nil)
		rootMock := rootRemote.mgr
		rootStaticSealer := newTestSealer(t)

		var rootSealCalled, rootUnsealCalled int
		rootMock.fnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			rootSealCalled++
			return rootStaticSealer.Seal(ctx, req)
		}
		rootMock.fnUnseal = func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			rootUnsealCalled++
			return rootStaticSealer.Unseal(ctx, req)
		}

		// shared database so key IDs resolve across agents
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		kStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		// --- middle agent (real Manager exposed via gRPC) ---
		middleMgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore:        kStore,
			KeyVersionStore: kvStore,
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K2": {
					SealerSpec:  newTestSealerSpec(t),
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{
						AgentName: "root",
					},
				},
				"K3": {
					CryptorSpec:       newTestCryptorSpec(),
					VaultSpec:         newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{},
				},
			},
			Hierarchy: spec.KeyHierarchy{
				Name: "middle-hierarchy",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
					{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
					{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
					{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
				},
			},
			Auth: nil,
			ParentConnection: config.ConnectionConfig{
				Name: "root",
				Address: config.Address{
					Type: config.AddressTypeGRPC,
					URL:  rootRemote.address,
				},
			},
		})
		require.NoError(t, err)

		// expose the middle Manager via gRPC, wrapped with call counters
		var middleSealCalled, middleUnsealCalled int
		middleMock := &mockmgr{
			fnSeal: func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
				middleSealCalled++
				return middleMgr.Seal(ctx, req)
			},
			fnUnseal: func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
				middleUnsealCalled++
				return middleMgr.Unseal(ctx, req)
			},
		}
		middlMgr := setupRemoteSealer(t, middleMock)

		// --- leaf agent (Manager under test) ---
		leafMgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore:        kStore,
			KeyVersionStore: kvStore,
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K4": {
					SealerSpec:  newTestSealerSpec(t),
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{
						AgentName: "middle",
					},
				},
				"K5": {
					CryptorSpec:       newTestCryptorSpec(),
					VaultSpec:         newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{},
				},
			},
			Hierarchy: spec.KeyHierarchy{
				Name: "leaf-hierarchy",
				KeySpecs: []spec.KeySpec{
					{Kind: "K0", Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
					{Kind: "K1", Role: spec.KeyRoleKek, Algorithm: cryptor.KeyAlgorithmAES256},
					{Kind: "K2", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
					{Kind: "K3", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
					{Kind: "K4", Role: spec.KeyRoleTek, Algorithm: cryptor.KeyAlgorithmAES256},
					{Kind: "K5", Role: spec.KeyRoleDek, Algorithm: cryptor.KeyAlgorithmAES256},
				},
			},
			Auth: nil,
			ParentConnection: config.ConnectionConfig{
				Name: "middle",
				Address: config.Address{
					Type: config.AddressTypeGRPC,
					URL:  middlMgr.address,
				},
			},
		})
		require.NoError(t, err)

		parentVersion := 1
		aad := []byte("test-aad")

		// seal K2's secret via the middle agent (delegates to remote "root")
		k2Key, k2kv := createTestKeyAndVersion(t, kStore, kvStore, tenantID, createKeyAndVersionParams{
			Kind:             "K2",
			ManagedBy:        "middle",
			VersionParentVer: &parentVersion,
		})

		_, err = middleMgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: k2kv,
			AAD:        aad,
			KeyKind:    k2Key.Kind,
		})
		require.NoError(t, err)

		// sealing K2 delegates to root (K2's parent is remote "root")
		assert.Equal(t, 1, rootSealCalled)
		assert.Equal(t, 0, rootUnsealCalled)

		// seal K3's secret via the middle agent (sealed locally using K2)
		k3Key, k3kv := createTestKeyAndVersion(t, kStore, kvStore, tenantID, createKeyAndVersionParams{
			Kind:               "K3",
			ManagedBy:          "middle",
			KeyParentID:        &k2Key.ID,
			VersionParentKeyID: &k2Key.ID,
			VersionParentVer:   &k2kv.Version,
		})

		_, err = middleMgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: k3kv,
			AAD:        aad,
			KeyKind:    k3Key.Kind,
		})
		require.NoError(t, err)

		// sealing K3 is local to the middle agent: no additional root seal, but
		// root unseal is needed to unseal K2 (K2's parent is remote "root")
		assert.Equal(t, 1, rootSealCalled)
		assert.Equal(t, 1, rootUnsealCalled)

		// seal K4's secret via the leaf agent (delegates to remote "middle")
		k4Key, k4kv := createTestKeyAndVersion(t, kStore, kvStore, tenantID, createKeyAndVersionParams{
			Kind:               "K4",
			ManagedBy:          "leaf",
			VersionParentKeyID: &k3Key.ID,
			VersionParentVer:   &k3kv.Version,
		})

		_, err = leafMgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: k4kv,
			AAD:        aad,
			KeyKind:    k4Key.Kind,
		})
		require.NoError(t, err)

		// sealing K4 delegates to the middle agent, which must unseal K3 to
		// encrypt K4's material. Unsealing K3 requires unsealing K2, which chains
		// to root.
		// middle: 1 seal (K4 sealed using K3's secret)
		// root:   1 unseal (K2 unsealed to resolve K3's secret)
		assert.Equal(t, 1, middleSealCalled)
		assert.Equal(t, 0, middleUnsealCalled)
		assert.Equal(t, 1, rootSealCalled)
		assert.Equal(t, 2, rootUnsealCalled)

		// seal K5's secret via the leaf agent (sealed locally using K4)
		k5Key, k5kv := createTestKeyAndVersion(t, kStore, kvStore, tenantID, createKeyAndVersionParams{
			Kind:               "K5",
			ManagedBy:          "leaf",
			KeyParentID:        &k4Key.ID,
			VersionParentKeyID: &k4Key.ID,
			VersionParentVer:   &k4kv.Version,
		})

		_, err = leafMgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: k5kv,
			AAD:        aad,
			KeyKind:    k5Key.Kind,
		})
		require.NoError(t, err)

		// sealing K5 is local to the leaf agent: the leaf must unseal K4 first,
		// which sends an unseal to the middle agent. The middle unseals K3 by
		// unsealing K2 via root.
		// middle: +1 unseal (K4 unsealed using K3's secret)
		// root:   +1 unseal (K2 unsealed to resolve K3's secret)
		assert.Equal(t, 1, middleSealCalled)
		assert.Equal(t, 1, middleUnsealCalled)
		assert.Equal(t, 1, rootSealCalled)
		assert.Equal(t, 3, rootUnsealCalled)

		// export K5's secret — this unseals K5 which chains through K4 -> middle -> K3 -> K2 -> root
		res, err := leafMgr.ExportSecret(ctx, keyprocessor.ExportSecretRequest{
			TenantID:   tenantID,
			KeyID:      k5Key.ID,
			KeyVersion: 1,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, res.Data)

		// exporting K5 requires unsealing K5 (local), which unseals K4 via middle,
		// which unseals K3 via K2 via root — one more unseal at each remote boundary.
		assert.Equal(t, 1, middleSealCalled)
		assert.Equal(t, 2, middleUnsealCalled)
		assert.Equal(t, 1, rootSealCalled)
		assert.Equal(t, 4, rootUnsealCalled)
	})

	//	k0 -> k1 -> k2 -> k3
	//	k0 - k1 : managed by the remote "root" agent (mocked via gRPC)
	//	k2 - k3 : managed by the agent
	// this test verifies that tampering with the root key
	// after a seal operation is detected and rejected.
	t.Run("should return error if root key is changed after sealing", func(t *testing.T) {
		ctx := t.Context()

		// setting up a remote sealer to simulate a parent key provider
		remoteManager := setupRemoteSealer(t, nil)
		rs := remoteManager.mgr
		staticSealer := newTestSealer(t)

		var remoteSealCalled, remoteUnsealCalled int

		rs.fnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			remoteSealCalled++
			return staticSealer.Seal(ctx, req)
		}

		rs.fnUnseal = func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			remoteUnsealCalled++
			return staticSealer.Unseal(ctx, req)
		}

		db := createDatabase(t)
		tenantID := createTenant(t, db)
		kStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		// creating a key processor manager with a remote parent key provider
		mgr, err := keyprocessor.NewManager(ctx, keyprocessor.ManagerConfig{
			KeyStore:        kStore,
			KeyVersionStore: kvStore,
			Bindings: map[model.KeyKind]spec.KeyBinding{
				"K2": {
					SealerSpec:  newTestSealerSpec(t),
					CryptorSpec: newTestCryptorSpec(),
					VaultSpec:   newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{
						AgentName: "root",
					},
				},
				"K3": {
					CryptorSpec:       newTestCryptorSpec(),
					VaultSpec:         newTestVaultSpec(),
					ParentKeyProvider: &spec.ParentKeyProviderRef{},
				},
			},
			Hierarchy: spec.KeyHierarchy{
				Name: "production-hierarchy",
				KeySpecs: []spec.KeySpec{
					{
						Kind:      "K0",
						Role:      spec.KeyRoleRoot,
						Algorithm: cryptor.KeyAlgorithmAES256,
					},
					{
						Kind:      "K1",
						Role:      spec.KeyRoleKek,
						Algorithm: cryptor.KeyAlgorithmAES256,
					},
					{
						Kind:      "K2",
						Role:      spec.KeyRoleTek,
						Algorithm: cryptor.KeyAlgorithmAES256,
					},
					{
						Kind:      "K3",
						Role:      spec.KeyRoleDek,
						Algorithm: cryptor.KeyAlgorithmAES256,
					},
				},
			},
			Auth: nil,
			ParentConnection: config.ConnectionConfig{
				Name: "root",
				Address: config.Address{
					Type: config.AddressTypeGRPC,
					URL:  remoteManager.address,
				},
			},
		})
		require.NoError(t, err)

		parentVersion := 1
		aad := []byte("test-aad")

		// seal K2's secret via the local manager (delegates to remote "root")
		k2Key, k2kv := createTestKeyAndVersion(t, kStore, kvStore, tenantID, createKeyAndVersionParams{
			Kind:             "K2",
			ManagedBy:        "agent",
			VersionParentVer: &parentVersion,
		})

		_, err = mgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: k2kv,
			AAD:        aad,
			KeyKind:    k2Key.Kind,
		})
		require.NoError(t, err)

		// sealing K2 delegates to the remote agent (K2's parent is remote "root"),
		// so remote seal is called once; no unseal needed yet
		assert.Equal(t, 1, remoteSealCalled)
		assert.Equal(t, 0, remoteUnsealCalled)

		// seal K3's secret via the local manager (sealed locally using K2)
		k3key, k3kv := createTestKeyAndVersion(t, kStore, kvStore, tenantID, createKeyAndVersionParams{
			Kind:               "K3",
			ManagedBy:          "agent",
			KeyParentID:        &k2Key.ID,
			VersionParentKeyID: &k2Key.ID,
			VersionParentVer:   &k2kv.Version,
		})

		_, err = mgr.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: k3kv,
			AAD:        aad,
			KeyKind:    k3key.Kind,
		})
		require.NoError(t, err)

		// sealing K3 is handled locally (K3's parent is the local manager),
		// so no additional remote seal is called. However, the local manager must
		// first unseal K2's secret to use it as the encryption key for K3, which
		// triggers one remote unseal (K2's parent is the remote "root" agent).
		assert.Equal(t, 1, remoteSealCalled)
		assert.Equal(t, 1, remoteUnsealCalled)

		// swapping the remote sealer with a new one to simulate a root key change
		newStaticSealer := newTestSealer(t)
		rs.fnSeal = func(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
			remoteSealCalled++
			return newStaticSealer.Seal(ctx, req)
		}

		rs.fnUnseal = func(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
			remoteUnsealCalled++
			return newStaticSealer.Unseal(ctx, req)
		}

		res, err := mgr.ExportSecret(ctx, keyprocessor.ExportSecretRequest{
			TenantID:   tenantID,
			KeyID:      k3key.ID,
			KeyVersion: 1,
		})

		// error is expected because the root key was changed after K2 was sealed, so unsealing K2 fails
		require.Error(t, err)
		assert.Empty(t, res.Data)

		// exporting K3's secret requires unsealing K3, which means unsealing K2
		// again via the remote agent. No additional remote seal is needed.
		assert.Equal(t, 1, remoteSealCalled)
		assert.Equal(t, 2, remoteUnsealCalled)
	})
}

type remoteManager struct {
	mgr     *mockmgr
	address string
}

type mockmgr struct {
	fnUnseal func(context.Context, cryptor.UnsealRequest) (cryptor.UnsealResponse, error)
	fnSeal   func(context.Context, cryptor.SealRequest) (cryptor.SealResponse, error)
}

var _ cryptor.Sealer = (*mockmgr)(nil)

// Seal implements [cryptor.Sealer].
func (m *mockmgr) Seal(ctx context.Context, req cryptor.SealRequest) (cryptor.SealResponse, error) {
	return m.fnSeal(ctx, req)
}

// Unseal implements [cryptor.Sealer].
func (m *mockmgr) Unseal(ctx context.Context, req cryptor.UnsealRequest) (cryptor.UnsealResponse, error) {
	return m.fnUnseal(ctx, req)
}

// createKeyAndVersionParams holds the per-key arguments for createTestKeyAndVersion.
type createKeyAndVersionParams struct {
	Kind               model.KeyKind
	ManagedBy          string
	KeyParentID        *string // parent key ID on the Key record
	VersionParentKeyID *string // parent key ID on the KeyVersion record
	VersionParentVer   *int    // parent key version on the KeyVersion record
}

// createTestKeyAndVersion creates a Key, activates it, and creates a version-1
// KeyVersion in the given stores. It returns both the Key and KeyVersion.
// If VersionParentKeyID is nil, the key's own ID is used (self-reference).
func createTestKeyAndVersion(t *testing.T, kStore store.Key, kvStore store.KeyVersion, tenantID string, p createKeyAndVersionParams) (model.Key, model.KeyVersion) {
	t.Helper()

	name := strings.ToLower(string(p.Kind)) + "-" + uuid.New().String()
	key := model.NewKey(tenantID, name, string(p.Kind), p.KeyParentID, p.ManagedBy, nil)
	require.NoError(t, kStore.CreateKey(t.Context(), key))
	activate(t, kStore, key)

	versionParentKeyID := p.VersionParentKeyID
	if versionParentKeyID == nil {
		versionParentKeyID = &key.ID
	}

	kv := model.NewKeyVersion(tenantID, key.ID, 1, versionParentKeyID, p.VersionParentVer)
	_, err := kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
	require.NoError(t, err)

	return key, kv
}

func setupRemoteSealer(t *testing.T, s cryptor.Sealer) remoteManager {
	t.Helper()

	mgr := &mockmgr{}
	if s == nil {
		s = newTestSealer(t)
	}
	mgr.fnSeal = s.Seal
	mgr.fnUnseal = s.Unseal

	var lc net.ListenConfig
	lis, err := lc.Listen(t.Context(), "tcp", "localhost:0")
	require.NoError(t, err)

	srv := grpc.NewServer(grpc.StatsHandler(securemem.NewRPCHandler()))
	sealer.RegisterServiceServer(srv, sealer.NewSealerService(mgr))

	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() { srv.GracefulStop() })

	return remoteManager{
		address: lis.Addr().String(),
		mgr:     mgr,
	}
}

func activate(t *testing.T, s store.Key, key model.Key) {
	t.Helper()
	require.NoError(t, s.UpdateKeyLifeCycleState(t.Context(), store.UpdateKeyLifeCycleStateQuery{
		ID:       key.ID,
		TenantID: key.TenantID,
		NewState: model.KeyLifeCycleActive,
	}))
}
