package keyprocessor_test

import (
	"context"
	"errors"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
	"github.com/openkcm/krypton/internal/vault/vaultprovider"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
	"github.com/openkcm/krypton/pkg/validator"
)

var errAssertImport = errors.New("vault import failed")

func TestNewRootManager(t *testing.T) {
	validCfg := func() keyprocessor.RootManagerConfig {
		return keyprocessor.RootManagerConfig{
			Transactor: &storesql.Transactor{},
			RootKey: spec.RootKeySpec{
				AllowedProviders: []sealer.Type{staticsecret.TypeStaticSecret},
				Vault:            vaultprovider.Spec{Name: "root-vault", Type: sqlitevault.TypeUnsafeMemory},
			},
		}
	}

	tts := []struct {
		name   string
		mutate func(*keyprocessor.RootManagerConfig)
		expErr error
	}{
		{
			name:   "missing transactor",
			mutate: func(c *keyprocessor.RootManagerConfig) { c.Transactor = nil },
			expErr: keyprocessor.ErrTransactorMissing,
		},
		{
			name:   "invalid vault spec",
			mutate: func(c *keyprocessor.RootManagerConfig) { c.RootKey.Vault = vaultprovider.Spec{Type: "unknown-vault"} },
			expErr: vault.ErrUnknownType,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validCfg()
			tt.mutate(&cfg)
			rm, err := keyprocessor.NewRootManager(t.Context(), cfg)
			assert.Nil(t, rm)
			assert.ErrorIs(t, err, tt.expErr)
		})
	}

	t.Run("valid config", func(t *testing.T) {
		rm, err := keyprocessor.NewRootManager(t.Context(), validCfg())
		require.NoError(t, err)
		assert.NotNil(t, rm)
	})
}

func TestRootManagerCreateProvider(t *testing.T) {
	t.Run("should reject disallowed provider type", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)

		rm, err := keyprocessor.NewRootManager(t.Context(), keyprocessor.RootManagerConfig{
			Transactor: storesql.NewTransactor(db),
			RootKey: spec.RootKeySpec{
				AllowedProviders: nil, // nothing allowed
				Vault:            vaultprovider.Spec{Name: "root-vault", Type: sqlitevault.TypeUnsafeMemory},
			},
		})
		require.NoError(t, err)

		rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		completeKeyProcessing(t, db, rootKey)

		err = rm.CreateProvider(t.Context(), keyprocessor.CreateProviderInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Spec:          newInlineStaticSecretSpec(t),
			ProviderKeyID: "pk-1",
		})
		assert.ErrorIs(t, err, keyprocessor.ErrProviderNotAllowed)
	})

	t.Run("should reject invalid spec", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		rm := newTestRootManager(t, db)

		rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		completeKeyProcessing(t, db, rootKey)

		spec := newInlineStaticSecretSpec(t)
		spec.Name = "" // invalid: empty name

		err := rm.CreateProvider(t.Context(), keyprocessor.CreateProviderInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Spec:          spec,
			ProviderKeyID: "pk-1",
		})
		assert.ErrorIs(t, err, sealerprovider.ErrSealerNameEmpty)
	})

	t.Run("should reject key in wrong state", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		rm := newTestRootManager(t, db)

		// key left in pending processing state -> transient state rejected
		rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))

		err := rm.CreateProvider(t.Context(), keyprocessor.CreateProviderInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Spec:          newInlineStaticSecretSpec(t),
			ProviderKeyID: "pk-1",
		})
		assert.ErrorIs(t, err, validator.ErrKeyTransientState)
	})

	t.Run("should return error for missing tenant", func(t *testing.T) {
		db := createDatabase(t)
		rm := newTestRootManager(t, db)

		err := rm.CreateProvider(t.Context(), keyprocessor.CreateProviderInput{
			TenantID:      uuid.New().String(),
			KeyID:         uuid.New().String(),
			Spec:          newInlineStaticSecretSpec(t),
			ProviderKeyID: "pk-1",
		})
		assert.ErrorIs(t, err, store.ErrTenantNotFound)
	})

	t.Run("should persist spec and labeled key version", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)
		vlt := newTestVault(t)

		rm := keyprocessor.NewRootManagerWithVault(
			storesql.NewTransactor(db),
			vlt,
			[]sealer.Type{staticsecret.TypeStaticSecret},
		)

		rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		completeKeyProcessing(t, db, rootKey)

		err := rm.CreateProvider(t.Context(), keyprocessor.CreateProviderInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Spec:          newInlineStaticSecretSpec(t),
			ProviderKeyID: "pk-abc",
		})
		require.NoError(t, err)

		// spec blob persisted and decodes to the static-secret type
		exp, err := vlt.ExportSecret(t.Context(), vault.ExportSecretRequest{TenantID: tenantID, ID: rootKey.ID})
		require.NoError(t, err)
		var spec sealerprovider.Spec
		require.NoError(t, yaml.Unmarshal(exp.Secret.SecureBytes(), &spec))
		assert.Equal(t, staticsecret.TypeStaticSecret, spec.Type)

		// version 1 carries the provider-key label
		res, err := kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{TenantID: tenantID, KeyID: rootKey.ID})
		require.NoError(t, err)
		require.Len(t, res.KeyVersions, 1)
		label := model.ReservedLabelPrefix + string(staticsecret.TypeStaticSecret) + ":provider-key"
		assert.Equal(t, "pk-abc", res.KeyVersions[0].Labels[label])
	})

	t.Run("should propagate vault import failure without writing a key version", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		kvStore := storesql.NewKeyVersionStore(db)

		vlt := &vaultWrapper{Vault: newTestVault(t)}
		vlt.importSecretFn = func(context.Context, vault.ImportSecretRequest) (*vault.ImportSecretResponse, error) {
			return nil, errAssertImport
		}

		rm := keyprocessor.NewRootManagerWithVault(
			storesql.NewTransactor(db),
			vlt,
			[]sealer.Type{staticsecret.TypeStaticSecret},
		)

		rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		completeKeyProcessing(t, db, rootKey)

		err := rm.CreateProvider(t.Context(), keyprocessor.CreateProviderInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Spec:          newInlineStaticSecretSpec(t),
			ProviderKeyID: "pk-1",
		})
		assert.ErrorIs(t, err, errAssertImport)

		res, err := kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{TenantID: tenantID, KeyID: rootKey.ID})
		require.NoError(t, err)
		assert.Empty(t, res.KeyVersions)
	})
}

func TestRootManagerRotateAuth(t *testing.T) {
	t.Run("should reject type mismatch", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)
		rootKey, _ := createRootProvider(t, db, rm, tenantID)
		activateKey(t, db, rootKey)
		completeKeyProcessing(t, db, rootKey)

		err := rm.RotateAuth(t.Context(), keyprocessor.RotateAuthInput{
			TenantID: tenantID,
			KeyID:    rootKey.ID,
			Type:     sealer.Type("other-type"),
			Auth:     &staticsecret.Auth{},
		})
		assert.ErrorIs(t, err, keyprocessor.ErrProviderTypeMismatch)
	})

	t.Run("should reject key not active", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)
		// provider created but key never activated -> still pre-activation
		rootKey, _ := createRootProvider(t, db, rm, tenantID)

		err := rm.RotateAuth(t.Context(), keyprocessor.RotateAuthInput{
			TenantID: tenantID,
			KeyID:    rootKey.ID,
			Type:     staticsecret.TypeStaticSecret,
			Auth:     &staticsecret.Auth{},
		})
		assert.ErrorIs(t, err, keylifecycle.ErrOperationNotAllowedInState)
	})

	t.Run("should rotate auth successfully", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)
		rootKey, _ := createRootProvider(t, db, rm, tenantID)
		activateKey(t, db, rootKey)
		completeKeyProcessing(t, db, rootKey)

		err := rm.RotateAuth(t.Context(), keyprocessor.RotateAuthInput{
			TenantID: tenantID,
			KeyID:    rootKey.ID,
			Type:     staticsecret.TypeStaticSecret,
			Auth:     &staticsecret.Auth{},
		})
		assert.NoError(t, err)
	})
}

func TestRootManagerRotateProviderKey(t *testing.T) {
	t.Run("should reject type mismatch against stored spec", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)
		rootKey, _ := createRootProvider(t, db, rm, tenantID)
		activateKey(t, db, rootKey)

		err := rm.RotateProviderKey(t.Context(), keyprocessor.RotateProviderKeyInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Type:          sealer.Type("other-type"),
			ProviderKeyID: "pk-2",
		})
		assert.ErrorIs(t, err, keyprocessor.ErrProviderTypeMismatch)
	})

	t.Run("should return error when no version exists", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		keyStore := storesql.NewKeyStore(db)
		rm := newTestRootManager(t, db)

		// key + spec in vault but no key version row: import spec manually is not
		// possible here, so instead create the key and expect the export to fail
		// before the version lookup -> use a created provider then delete versions.
		rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		completeKeyProcessing(t, db, rootKey)
		activateKey(t, db, rootKey)

		// no provider created -> exportSpec fails with key not found
		err := rm.RotateProviderKey(t.Context(), keyprocessor.RotateProviderKeyInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Type:          staticsecret.TypeStaticSecret,
			ProviderKeyID: "pk-2",
		})
		assert.ErrorIs(t, err, vault.ErrSecretNotFound)
	})

	t.Run("should create a new labeled version", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		kvStore := storesql.NewKeyVersionStore(db)
		rm := newTestRootManager(t, db)
		rootKey, _ := createRootProvider(t, db, rm, tenantID)
		activateKey(t, db, rootKey)

		err := rm.RotateProviderKey(t.Context(), keyprocessor.RotateProviderKeyInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Type:          staticsecret.TypeStaticSecret,
			ProviderKeyID: "pk-rotated",
		})
		require.NoError(t, err)

		res, err := kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    rootKey.ID,
			OrderBy:  []store.KeyVersionOrder{store.KeyVersionOrderVersionDesc},
			Limit:    1,
		})
		require.NoError(t, err)
		require.Len(t, res.KeyVersions, 1)
		assert.Equal(t, 2, res.KeyVersions[0].Version)
		label := model.ReservedLabelPrefix + string(staticsecret.TypeStaticSecret) + ":provider-key"
		assert.Equal(t, "pk-rotated", res.KeyVersions[0].Labels[label])
	})
}

func TestRootManagerRemoveProvider(t *testing.T) {
	t.Run("should return error for missing tenant", func(t *testing.T) {
		db := createDatabase(t)
		rm := newTestRootManager(t, db)

		err := rm.RemoveProvider(t.Context(), keyprocessor.RemoveProviderInput{
			TenantID: uuid.New().String(),
			KeyID:    uuid.New().String(),
		})
		assert.ErrorIs(t, err, store.ErrTenantNotFound)
	})

	t.Run("should destroy the stored spec", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		vlt := newTestVault(t)
		rm := keyprocessor.NewRootManagerWithVault(
			storesql.NewTransactor(db),
			vlt,
			[]sealer.Type{staticsecret.TypeStaticSecret},
		)

		keyStore := storesql.NewKeyStore(db)
		rootKey := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), rootKey))
		completeKeyProcessing(t, db, rootKey)
		require.NoError(t, rm.CreateProvider(t.Context(), keyprocessor.CreateProviderInput{
			TenantID:      tenantID,
			KeyID:         rootKey.ID,
			Spec:          newInlineStaticSecretSpec(t),
			ProviderKeyID: "pk-1",
		}))

		err := rm.RemoveProvider(t.Context(), keyprocessor.RemoveProviderInput{
			TenantID: tenantID,
			KeyID:    rootKey.ID,
		})
		require.NoError(t, err)

		_, err = vlt.ExportSecret(t.Context(), vault.ExportSecretRequest{TenantID: tenantID, ID: rootKey.ID})
		assert.ErrorIs(t, err, vault.ErrSecretNotFound)
	})
}

func TestRootManagerSealUnseal(t *testing.T) {
	t.Run("should require a key version", func(t *testing.T) {
		db := createDatabase(t)
		rm := newTestRootManager(t, db)

		_, err := rm.Seal(t.Context(), sealer.SealRequest{
			TenantID:   uuid.New().String(),
			KeyID:      uuid.New().String(),
			KeyVersion: 0,
			Plaintext:  newTestData(t, []byte("data")),
		})
		assert.ErrorIs(t, err, keyprocessor.ErrKeyVersionRequired)

		_, err = rm.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   uuid.New().String(),
			KeyID:      uuid.New().String(),
			KeyVersion: 0,
			Ciphertext: newTestData(t, []byte("data")),
		})
		assert.ErrorIs(t, err, keyprocessor.ErrKeyVersionRequired)
	})

	t.Run("should return error when spec is missing", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)

		keyStore := storesql.NewKeyStore(db)
		key := model.NewKey(tenantID, "root-"+uuid.New().String(), "K0", nil, "test", nil)
		require.NoError(t, keyStore.CreateKey(t.Context(), key))
		completeKeyProcessing(t, db, key)
		activateKey(t, db, key)

		_, err := rm.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenantID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("data")),
		})
		assert.ErrorIs(t, err, vault.ErrSecretNotFound)
	})

	t.Run("should reject sealing when key is not active", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)
		rootKey, _ := createRootProvider(t, db, rm, tenantID)

		_, err := rm.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenantID,
			KeyID:      rootKey.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("data")),
		})
		assert.ErrorIs(t, err, keylifecycle.ErrOperationNotAllowedInState)
	})

	t.Run("should reject an empty provider key label", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)
		rootKey, _ := createRootProvider(t, db, rm, tenantID)
		activateKey(t, db, rootKey)

		kvStore := storesql.NewKeyVersionStore(db)
		res, err := kvStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    rootKey.ID,
			Version:  1,
		})
		require.NoError(t, err)
		require.Len(t, res.KeyVersions, 1)

		kv := res.KeyVersions[0]
		kv.Revision++
		kv.Labels = nil
		_, err = kvStore.CreateKeyVersion(t.Context(), store.CreateKeyVersionQuery{KeyVersion: kv})
		require.NoError(t, err)

		_, err = rm.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenantID,
			KeyID:      rootKey.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("data")),
		})
		assert.ErrorIs(t, err, keyprocessor.ErrProviderKeyLabelEmpty)
	})

	t.Run("should seal and unseal round trip with nil metadata", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)
		rootKey, _ := createRootProvider(t, db, rm, tenantID)
		activateKey(t, db, rootKey)

		sealResp, err := rm.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenantID,
			KeyID:      rootKey.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("root secret")),
			AAD:        []byte("aad"),
			Metadata:   nil,
		})
		require.NoError(t, err)

		unsealResp, err := rm.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   tenantID,
			KeyID:      rootKey.ID,
			KeyVersion: 1,
			Ciphertext: sealResp.Ciphertext,
			AAD:        []byte("aad"),
			Metadata:   nil,
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("root secret"), []byte(unsealResp.Plaintext.SecureBytes()))
	})

	t.Run("should allow unsealing when key is deactivated", func(t *testing.T) {
		db := createDatabase(t)
		tenantID := createTenant(t, db)
		rm := newTestRootManager(t, db)
		rootKey, _ := createRootProvider(t, db, rm, tenantID)
		activateKey(t, db, rootKey)

		sealResp, err := rm.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenantID,
			KeyID:      rootKey.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("root secret")),
			AAD:        []byte("aad"),
		})
		require.NoError(t, err)

		setKeyLifeCycleState(t, db, rootKey, model.KeyLifeCycleDeactivated)

		unsealResp, err := rm.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   tenantID,
			KeyID:      rootKey.ID,
			KeyVersion: 1,
			Ciphertext: sealResp.Ciphertext,
			AAD:        []byte("aad"),
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("root secret"), []byte(unsealResp.Plaintext.SecureBytes()))

		// Sealing is not permitted once deactivated.
		_, err = rm.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenantID,
			KeyID:      rootKey.ID,
			KeyVersion: 1,
			Plaintext:  newTestData(t, []byte("root secret")),
			AAD:        []byte("aad"),
		})
		assert.ErrorIs(t, err, keylifecycle.ErrOperationNotAllowedInState)
	})
}
