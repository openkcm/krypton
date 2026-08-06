package kmip_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

const (
	rootKind model.KeyKind = "K0"
	dekKind  model.KeyKind = "K1"
)

// keyStoreStub implements store.Key with an overridable GetKeyByID.
type keyStoreStub struct {
	store.Key

	getKeyByIDFn func(ctx context.Context, id, tenantID string) (*model.Key, error)
}

func (s *keyStoreStub) GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error) {
	return s.getKeyByIDFn(ctx, id, tenantID)
}

// keyVersionStoreStub implements store.KeyVersion with an overridable
// ListKeyVersions.
type keyVersionStoreStub struct {
	store.KeyVersion

	listKeyVersionsFn func(ctx context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error)
}

func (s *keyVersionStoreStub) ListKeyVersions(ctx context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
	return s.listKeyVersionsFn(ctx, q)
}

// testEnv is a real *keyprocessor.Manager wired to stub stores and a
// file-backed sqlite vault that tests seed out of band.
type testEnv struct {
	mgr       *keyprocessor.Manager
	keys      *keyStoreStub
	kvs       *keyVersionStoreStub
	vaultPath string
	sealerKey []byte

	tenantID  string
	rootKeyID string
	keyID     string
}

// newTestEnv builds a real manager over a two-level hierarchy (root sealer +
// DEK kind with aes256gcm and a file sqlite vault). The default stubs serve
// an active root and DEK key with one usable version "1".
func newTestEnv(t *testing.T, tenantID, keyID string) *testEnv {
	t.Helper()
	return newTestEnvWithAlgorithm(t, tenantID, keyID, cryptor.KeyAlgorithmAES256)
}

// newTestEnvWithAlgorithm is newTestEnv with the DEK kind's spec algorithm
// parameterized, so tests can exercise the unsupported-algorithm path.
func newTestEnvWithAlgorithm(t *testing.T, tenantID, keyID string, alg cryptor.KeyAlgorithm) *testEnv {
	t.Helper()

	sealerKey := make([]byte, 32)
	_, err := rand.Read(sealerKey)
	require.NoError(t, err)
	envName := "TEST_KMIP_SEALER_KEY"
	t.Setenv(envName, base64.StdEncoding.EncodeToString(sealerKey))

	env := &testEnv{
		vaultPath: filepath.Join(t.TempDir(), "vault.db"),
		sealerKey: sealerKey,
		tenantID:  tenantID,
		rootKeyID: "root-" + keyID,
		keyID:     keyID,
	}

	rootKey := &model.Key{ID: env.rootKeyID, TenantID: tenantID, Kind: rootKind, LifeCycleState: model.KeyLifeCycleActive}
	dekKey := &model.Key{ID: keyID, TenantID: tenantID, Kind: dekKind, LifeCycleState: model.KeyLifeCycleActive}
	env.keys = &keyStoreStub{getKeyByIDFn: func(_ context.Context, id, tid string) (*model.Key, error) {
		if tid != tenantID {
			return nil, store.ErrKeyNotFound
		}
		switch id {
		case rootKey.ID:
			return rootKey, nil
		case dekKey.ID:
			return dekKey, nil
		default:
			return nil, store.ErrKeyNotFound
		}
	}}
	env.kvs = &keyVersionStoreStub{listKeyVersionsFn: func(_ context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
		if q.TenantID != tenantID || q.KeyID != dekKey.ID || (q.Version != 0 && q.Version != 1) {
			return store.ListKeyVersionsResult{}, nil
		}
		return store.ListKeyVersionsResult{KeyVersions: []model.KeyVersion{{
			TenantID:        tenantID,
			KeyID:           dekKey.ID,
			Version:         1,
			Revision:        0,
			ParentKeyID:     &rootKey.ID,
			LifeCycleState:  model.KeyLifeCycleActive,
			ProcessingState: model.KeyVersionUsable,
		}}}, nil
	}}

	env.mgr, err = keyprocessor.NewManager(t.Context(), keyprocessor.ManagerConfig{
		KeyStore:        env.keys,
		KeyVersionStore: env.kvs,
		Bindings: map[model.KeyKind]spec.KeyBinding{
			rootKind: {
				SealerSpec: &sealerprovider.Spec{
					Name: "test-sealer",
					Type: staticsecret.TypeStaticSecret,
					Config: &staticsecret.Config{
						Secret: secretprovider.Spec{
							Type:   envvar.Type,
							Config: &envvar.Config{Name: envName},
						},
					},
				},
			},
			dekKind: {
				CryptorSpec: &cryptorprovider.Spec{
					Name:   "test-cryptor",
					Type:   aes256gcm.TypeAES256GCM,
					Config: &aes256gcm.Config{},
				},
				VaultSpec: &vaultprovider.Spec{
					Name:   "test-vault",
					Type:   sqlitevault.TypeUnsafe,
					Config: &sqlitevault.FileConfig{Path: env.vaultPath},
				},
			},
		},
		Hierarchy: spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: rootKind, Role: spec.KeyRoleRoot, Algorithm: cryptor.KeyAlgorithmAES256},
				{Kind: dekKind, Role: spec.KeyRoleDek, Algorithm: alg},
			},
		},
	})
	require.NoError(t, err, "keyprocessor.NewManager")
	return env
}

// seedSecret plants material as the DEK's version "1" through a second handle
// on the vault file, in the same shape createSecret produces (root-sealed, no
// transport sealer, nil AAD).
func (env *testEnv) seedSecret(t *testing.T, material []byte) {
	t.Helper()
	ctx := t.Context()

	keyData := newSecureData(t, "seed-sealer-key", env.sealerKey)
	defer func() { require.NoError(t, keyData.Destroy()) }()
	sealer, err := staticsecret.New("test-sealer", keyData)
	require.NoError(t, err, "staticsecret.New")

	plain := newSecureData(t, "seed-material", material)
	sealed, err := sealer.Seal(ctx, cryptor.SealRequest{
		TenantID:  env.tenantID,
		KeyID:     env.rootKeyID,
		Plaintext: plain,
	})
	require.NoError(t, err, "seal seed material")

	v, err := sqlitevault.NewUnsafe(ctx, "seed-vault", sqlitevault.FileSource(env.vaultPath))
	require.NoError(t, err, "open seed vault")
	_, err = v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    env.tenantID,
		KeyID:       env.keyID,
		KeyVersion:  1,
		KeyRevision: 0,
		KeyMaterial: sealed.Ciphertext,
	})
	require.NoError(t, err, "import seed material")
}

// failingEnv returns an env whose key version store fails with storeErr.
func failingEnv(t *testing.T, tenantID, keyID string, storeErr error) *testEnv {
	t.Helper()
	env := newTestEnv(t, tenantID, keyID)
	env.kvs.listKeyVersionsFn = func(context.Context, store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
		return store.ListKeyVersionsResult{}, storeErr
	}
	return env
}

// newSecureData copies b into a fresh secure-memory region.
func newSecureData(t *testing.T, name string, b []byte) *securemem.Data {
	t.Helper()
	d, err := securemem.NewData(name, len(b))
	require.NoError(t, err, "securemem.NewData")
	copy(d.SecureBytes(), b)
	return d
}

// sequentialMaterial returns n bytes 0..n-1.
func sequentialMaterial(n int) []byte {
	material := make([]byte, n)
	for i := range material {
		material[i] = byte(i)
	}
	return material
}

// errMustNotBeCalled backs envs whose request must be rejected before the
// manager is consulted.
var errMustNotBeCalled = errors.New("manager must not be called")
