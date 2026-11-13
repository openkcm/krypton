package rootkey_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/providertest"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

func TestCreateProvider(t *testing.T) {
	db := createDatabase(t)
	setup := setupServerAndClient(t, db, providertest.TypeProviderTest)
	tenant := createTenant(t, setup.tenantStore)

	t.Run("creates a usable provider binding", func(t *testing.T) {
		provisionTestProvider(t)

		// Bind the externally provisioned provider to the root key through the API.
		key := createRootKey(t, setup.keyStore, tenant.ID, true)
		response, err := setup.client.CreateProvider(t.Context(), validCreateRequest(tenant.ID, key.ID))
		require.NoError(t, err)
		assert.NotNil(t, response)
		activateKey(t, setup.keyStore, key)

		result, err := setup.keyVersionStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
		})
		require.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		label := model.ReservedLabelPrefix + string(providertest.TypeProviderTest) + ":provider-key"
		assert.Equal(t, "provider-key-1", result.KeyVersions[0].Labels[label])

		// The resulting binding can seal and unseal through the external provider.
		sealed, err := setup.root.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Plaintext:  newSecureData(t, "root secret"),
			AAD:        []byte("aad"),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealed.Ciphertext.Destroy() })

		unsealed, err := setup.root.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Ciphertext: sealed.Ciphertext,
			AAD:        []byte("aad"),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = unsealed.Plaintext.Destroy() })
		assert.Equal(t, "root secret", string(unsealed.Plaintext.SecureBytes()))
	})

	t.Run("validates request", func(t *testing.T) {
		tests := []struct {
			name    string
			mutate  func(*rootkey.CreateProviderRequest)
			wantMsg string
		}{
			{
				name:    "invalid tenant id",
				mutate:  func(req *rootkey.CreateProviderRequest) { req.TenantId = "invalid" },
				wantMsg: rootkey.ErrInvalidTenantID.Error(),
			},
			{
				name:    "invalid key id",
				mutate:  func(req *rootkey.CreateProviderRequest) { req.KeyId = "invalid" },
				wantMsg: rootkey.ErrInvalidKeyID.Error(),
			},
			{
				name: "missing provider key id",
				mutate: func(req *rootkey.CreateProviderRequest) {
					req.Provider.GetTestProvider().ProviderKey.KeyId = ""
				},
				wantMsg: rootkey.ErrProviderKeyRequired.Error(),
			},
			{
				name: "missing provider instance",
				mutate: func(req *rootkey.CreateProviderRequest) {
					req.Provider.GetTestProvider().Config.InstanceId = ""
				},
				wantMsg: providertest.ErrInstanceIDMissing.Error(),
			},
			{
				name: "missing access token",
				mutate: func(req *rootkey.CreateProviderRequest) {
					req.Provider.GetTestProvider().Auth.AccessToken = ""
				},
				wantMsg: providertest.ErrAccessTokenMissing.Error(),
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := validCreateRequest(tenant.ID, uuid.New().String())
				tt.mutate(req)
				_, err := setup.client.CreateProvider(t.Context(), req)
				assertRPCError(t, err, codes.InvalidArgument, proto.Code_ERROR_CODE_ABORT)
				assert.Equal(t, tt.wantMsg, status.Convert(err).Message())
			})
		}
	})

	t.Run("rejects unsupported provider", func(t *testing.T) {
		req := validCreateRequest(tenant.ID, uuid.New().String())
		req.Provider.Provider = &rootkey.Provider_AwsKms{AwsKms: &rootkey.AwsKmsProvider{}}
		_, err := setup.client.CreateProvider(t.Context(), req)
		assertRPCError(t, err, codes.Unimplemented, proto.Code_ERROR_CODE_ABORT)
		assert.Equal(t, rootkey.ErrUnsupportedProvider.Error(), status.Convert(err).Message())
	})

	t.Run("returns not found for missing tenant", func(t *testing.T) {
		_, err := setup.client.CreateProvider(t.Context(), validCreateRequest(uuid.New().String(), uuid.New().String()))
		assertRPCError(t, err, codes.NotFound, proto.Code_ERROR_CODE_ABORT)
		assert.Equal(t, "tenant not found", status.Convert(err).Message())
	})

	t.Run("returns not found for missing key", func(t *testing.T) {
		_, err := setup.client.CreateProvider(t.Context(), validCreateRequest(tenant.ID, uuid.New().String()))
		assertRPCError(t, err, codes.NotFound, proto.Code_ERROR_CODE_ABORT)
		assert.Equal(t, "key not found", status.Convert(err).Message())
	})

	t.Run("rejects transient key", func(t *testing.T) {
		key := createRootKey(t, setup.keyStore, tenant.ID, false)
		_, err := setup.client.CreateProvider(t.Context(), validCreateRequest(tenant.ID, key.ID))
		assertRPCError(t, err, codes.FailedPrecondition, proto.Code_ERROR_CODE_ABORT)
	})

	t.Run("rejects disallowed provider", func(t *testing.T) {
		disallowed := setupServerAndClient(t, db)
		key := createRootKey(t, disallowed.keyStore, tenant.ID, true)
		_, err := disallowed.client.CreateProvider(t.Context(), validCreateRequest(tenant.ID, key.ID))
		assertRPCError(t, err, codes.FailedPrecondition, proto.Code_ERROR_CODE_ABORT)
	})
}

func TestRotateAuth(t *testing.T) {
	db := createDatabase(t)
	setup := setupServerAndClient(t, db, providertest.TypeProviderTest)
	provider := provisionTestProvider(t)
	tenant := createTenant(t, setup.tenantStore)
	key := createRootKey(t, setup.keyStore, tenant.ID, true)
	createProvider(t, setup, tenant.ID, key.ID)
	activateKey(t, setup.keyStore, key)

	validRequest := func() *rootkey.RotateAuthRequest {
		return &rootkey.RotateAuthRequest{
			TenantId: tenant.ID,
			KeyId:    key.ID,
			Auth: &rootkey.ProviderAuth{Provider: &rootkey.ProviderAuth_TestProvider{
				TestProvider: &rootkey.TestProviderAuth{AccessToken: "replacement-token"},
			}},
		}
	}

	t.Run("observes external auth rotation", func(t *testing.T) {
		sealed, err := setup.root.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Plaintext:  newSecureData(t, "root secret"),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealed.Ciphertext.Destroy() })

		// The provider rotates first, so Krypton's stored credentials are temporarily stale.
		require.NoError(t, provider.UpsertKeyAuth(
			t.Context(), "provider-instance", "provider-key-1", "replacement-token",
		))
		_, err = setup.root.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Ciphertext: sealed.Ciphertext,
		})
		assert.ErrorIs(t, err, providertest.ErrUnauthorized)

		// Rotating the binding auth brings Krypton back in sync.
		response, err := setup.client.RotateAuth(t.Context(), validRequest())
		require.NoError(t, err)
		assert.NotNil(t, response)

		unsealed, err := setup.root.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Ciphertext: sealed.Ciphertext,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = unsealed.Plaintext.Destroy() })
		assert.Equal(t, "root secret", string(unsealed.Plaintext.SecureBytes()))
	})

	t.Run("validates ids", func(t *testing.T) {
		req := validRequest()
		req.TenantId = "invalid"
		_, err := setup.client.RotateAuth(t.Context(), req)
		assertRPCError(t, err, codes.InvalidArgument, proto.Code_ERROR_CODE_ABORT)

		req = validRequest()
		req.KeyId = "invalid"
		_, err = setup.client.RotateAuth(t.Context(), req)
		assertRPCError(t, err, codes.InvalidArgument, proto.Code_ERROR_CODE_ABORT)
	})

	t.Run("rejects unsupported auth", func(t *testing.T) {
		req := validRequest()
		req.Auth.Provider = &rootkey.ProviderAuth_AwsKms{AwsKms: &rootkey.AwsKmsAuth{}}
		_, err := setup.client.RotateAuth(t.Context(), req)
		assertRPCError(t, err, codes.Unimplemented, proto.Code_ERROR_CODE_ABORT)
	})

	t.Run("returns not found when provider is missing", func(t *testing.T) {
		otherKey := createRootKey(t, setup.keyStore, tenant.ID, true)
		activateKey(t, setup.keyStore, otherKey)
		req := validRequest()
		req.KeyId = otherKey.ID
		_, err := setup.client.RotateAuth(t.Context(), req)
		assertRPCError(t, err, codes.NotFound, proto.Code_ERROR_CODE_ABORT)
		assert.Equal(t, "key not found", status.Convert(err).Message())
	})
}

func TestRotateProviderKey(t *testing.T) {
	db := createDatabase(t)
	setup := setupServerAndClient(t, db, providertest.TypeProviderTest)
	provider := provisionTestProvider(t)
	tenant := createTenant(t, setup.tenantStore)
	key := createRootKey(t, setup.keyStore, tenant.ID, true)
	createProvider(t, setup, tenant.ID, key.ID)
	activateKey(t, setup.keyStore, key)

	validRequest := func() *rootkey.RotateProviderKeyRequest {
		return &rootkey.RotateProviderKeyRequest{
			TenantId: tenant.ID,
			KeyId:    key.ID,
			ProviderKey: &rootkey.ProviderKey{Provider: &rootkey.ProviderKey_TestProvider{
				TestProvider: &rootkey.TestProviderKey{KeyId: "provider-key-2"},
			}},
		}
	}

	t.Run("observes provider key rotation", func(t *testing.T) {
		sealedV1, err := setup.root.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Plaintext:  newSecureData(t, "root secret"),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealedV1.Ciphertext.Destroy() })

		// Auth exists for the replacement key, but its key material has not been provisioned yet.
		require.NoError(t, provider.UpsertKeyAuth(
			t.Context(), "provider-instance", "provider-key-2", "access-token",
		))
		response, err := setup.client.RotateProviderKey(t.Context(), validRequest())
		require.NoError(t, err)
		assert.NotNil(t, response)

		result, err := setup.keyVersionStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
			OrderBy:  []store.KeyVersionOrder{store.KeyVersionOrderVersionDesc},
			Limit:    1,
		})
		require.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		assert.Equal(t, 2, result.KeyVersions[0].Version)
		label := model.ReservedLabelPrefix + string(providertest.TypeProviderTest) + ":provider-key"
		assert.Equal(t, "provider-key-2", result.KeyVersions[0].Labels[label])

		_, err = setup.root.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 2,
			Plaintext:  newSecureData(t, "root secret"),
		})
		assert.ErrorIs(t, err, providertest.ErrKeyNotFound)

		// Once the replacement key exists, the new version is usable.
		require.NoError(t, provider.UpsertKey(t.Context(), "provider-instance", "provider-key-2"))
		sealedV2, err := setup.root.Seal(t.Context(), sealer.SealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 2,
			Plaintext:  newSecureData(t, "root secret"),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealedV2.Ciphertext.Destroy() })

		unsealedV2, err := setup.root.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 2,
			Ciphertext: sealedV2.Ciphertext,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = unsealedV2.Plaintext.Destroy() })
		assert.Equal(t, "root secret", string(unsealedV2.Plaintext.SecureBytes()))

		// Existing ciphertext remains tied to and readable through version 1.
		unsealedV1, err := setup.root.Unseal(t.Context(), sealer.UnsealRequest{
			TenantID:   tenant.ID,
			KeyID:      key.ID,
			KeyVersion: 1,
			Ciphertext: sealedV1.Ciphertext,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = unsealedV1.Plaintext.Destroy() })
		assert.Equal(t, "root secret", string(unsealedV1.Plaintext.SecureBytes()))
	})

	t.Run("requires provider key id", func(t *testing.T) {
		req := validRequest()
		req.ProviderKey.GetTestProvider().KeyId = ""
		_, err := setup.client.RotateProviderKey(t.Context(), req)
		assertRPCError(t, err, codes.InvalidArgument, proto.Code_ERROR_CODE_ABORT)
	})

	t.Run("rejects unsupported provider", func(t *testing.T) {
		req := validRequest()
		req.ProviderKey.Provider = &rootkey.ProviderKey_AwsKms{AwsKms: &rootkey.AwsKmsKey{}}
		_, err := setup.client.RotateProviderKey(t.Context(), req)
		assertRPCError(t, err, codes.Unimplemented, proto.Code_ERROR_CODE_ABORT)
	})

	t.Run("returns not found when provider is missing", func(t *testing.T) {
		otherKey := createRootKey(t, setup.keyStore, tenant.ID, true)
		activateKey(t, setup.keyStore, otherKey)
		req := validRequest()
		req.KeyId = otherKey.ID
		_, err := setup.client.RotateProviderKey(t.Context(), req)
		assertRPCError(t, err, codes.NotFound, proto.Code_ERROR_CODE_ABORT)
	})
}

func TestRemoveProvider(t *testing.T) {
	db := createDatabase(t)
	setup := setupServerAndClient(t, db, providertest.TypeProviderTest)
	tenant := createTenant(t, setup.tenantStore)
	key := createRootKey(t, setup.keyStore, tenant.ID, true)
	createProvider(t, setup, tenant.ID, key.ID)

	t.Run("removes provider", func(t *testing.T) {
		response, err := setup.client.RemoveProvider(t.Context(), &rootkey.RemoveProviderRequest{
			TenantId: tenant.ID,
			KeyId:    key.ID,
		})
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("is idempotent", func(t *testing.T) {
		response, err := setup.client.RemoveProvider(t.Context(), &rootkey.RemoveProviderRequest{
			TenantId: tenant.ID,
			KeyId:    key.ID,
		})
		require.NoError(t, err)
		assert.NotNil(t, response)
	})

	t.Run("validates ids", func(t *testing.T) {
		_, err := setup.client.RemoveProvider(t.Context(), &rootkey.RemoveProviderRequest{
			TenantId: "invalid",
			KeyId:    key.ID,
		})
		assertRPCError(t, err, codes.InvalidArgument, proto.Code_ERROR_CODE_ABORT)

		_, err = setup.client.RemoveProvider(t.Context(), &rootkey.RemoveProviderRequest{
			TenantId: tenant.ID,
			KeyId:    "invalid",
		})
		assertRPCError(t, err, codes.InvalidArgument, proto.Code_ERROR_CODE_ABORT)
	})

	t.Run("returns not found for missing tenant", func(t *testing.T) {
		_, err := setup.client.RemoveProvider(t.Context(), &rootkey.RemoveProviderRequest{
			TenantId: uuid.New().String(),
			KeyId:    uuid.New().String(),
		})
		assertRPCError(t, err, codes.NotFound, proto.Code_ERROR_CODE_ABORT)
	})
}
