package rootkey_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

func TestCreateProvider(t *testing.T) {
	db := createDatabase(t)
	setup := setupServerAndClient(t, db, staticsecret.TypeStaticSecret)
	tenant := createTenant(t, setup.tenantStore)

	t.Run("creates provider", func(t *testing.T) {
		key := createRootKey(t, setup.keyStore, tenant.ID, true)
		response, err := setup.client.CreateProvider(t.Context(), validCreateRequest(tenant.ID, key.ID))
		require.NoError(t, err)
		assert.NotNil(t, response)

		result, err := setup.keyVersionStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
			TenantID: tenant.ID,
			KeyID:    key.ID,
		})
		require.NoError(t, err)
		require.Len(t, result.KeyVersions, 1)
		label := model.ReservedLabelPrefix + string(staticsecret.TypeStaticSecret) + ":provider-key"
		assert.Equal(t, "provider-key-1", result.KeyVersions[0].Labels[label])
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
					req.ProviderKey.GetStaticSecret().Id = ""
				},
				wantMsg: rootkey.ErrProviderKeyRequired.Error(),
			},
			{
				name: "missing secret",
				mutate: func(req *rootkey.CreateProviderRequest) {
					req.Config.GetStaticSecret().Secret = nil
				},
				wantMsg: rootkey.ErrSecretRequired.Error(),
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

	t.Run("rejects unsupported providers", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(*rootkey.CreateProviderRequest)
		}{
			{
				name: "provider key",
				mutate: func(req *rootkey.CreateProviderRequest) {
					req.ProviderKey.Provider = &rootkey.ProviderKey_AwsKms{AwsKms: &rootkey.AwsKmsKey{}}
				},
			},
			{
				name: "auth",
				mutate: func(req *rootkey.CreateProviderRequest) {
					req.Auth.Provider = &rootkey.ProviderAuth_AwsKms{AwsKms: &rootkey.AwsKmsAuth{}}
				},
			},
			{
				name: "config",
				mutate: func(req *rootkey.CreateProviderRequest) {
					req.Config.Provider = &rootkey.ProviderConfig_AwsKms{AwsKms: &rootkey.AwsKmsConfig{}}
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				req := validCreateRequest(tenant.ID, uuid.New().String())
				tt.mutate(req)
				_, err := setup.client.CreateProvider(t.Context(), req)
				assertRPCError(t, err, codes.Unimplemented, proto.Code_ERROR_CODE_ABORT)
				assert.Equal(t, rootkey.ErrUnsupportedProvider.Error(), status.Convert(err).Message())
			})
		}
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
	setup := setupServerAndClient(t, db, staticsecret.TypeStaticSecret)
	tenant := createTenant(t, setup.tenantStore)
	key := createRootKey(t, setup.keyStore, tenant.ID, true)
	createProvider(t, setup, tenant.ID, key.ID)
	activateKey(t, setup.keyStore, key)

	validRequest := func() *rootkey.RotateAuthRequest {
		return &rootkey.RotateAuthRequest{
			TenantId: tenant.ID,
			KeyId:    key.ID,
			Auth: &rootkey.ProviderAuth{Provider: &rootkey.ProviderAuth_StaticSecret{
				StaticSecret: &rootkey.StaticSecretAuth{},
			}},
		}
	}

	t.Run("rotates auth", func(t *testing.T) {
		response, err := setup.client.RotateAuth(t.Context(), validRequest())
		require.NoError(t, err)
		assert.NotNil(t, response)
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
	setup := setupServerAndClient(t, db, staticsecret.TypeStaticSecret)
	tenant := createTenant(t, setup.tenantStore)
	key := createRootKey(t, setup.keyStore, tenant.ID, true)
	createProvider(t, setup, tenant.ID, key.ID)
	activateKey(t, setup.keyStore, key)

	validRequest := func() *rootkey.RotateProviderKeyRequest {
		return &rootkey.RotateProviderKeyRequest{
			TenantId: tenant.ID,
			KeyId:    key.ID,
			ProviderKey: &rootkey.ProviderKey{Provider: &rootkey.ProviderKey_StaticSecret{
				StaticSecret: &rootkey.StaticSecretKey{Id: "provider-key-2"},
			}},
		}
	}

	t.Run("rotates provider key", func(t *testing.T) {
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
		label := model.ReservedLabelPrefix + string(staticsecret.TypeStaticSecret) + ":provider-key"
		assert.Equal(t, "provider-key-2", result.KeyVersions[0].Labels[label])
	})

	t.Run("requires provider key id", func(t *testing.T) {
		req := validRequest()
		req.ProviderKey.GetStaticSecret().Id = ""
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
	setup := setupServerAndClient(t, db, staticsecret.TypeStaticSecret)
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
