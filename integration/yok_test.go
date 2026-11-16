package integration

import (
	"database/sql"
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/providertest"
	admingrpc "github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	keygrpc "github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	sealergrpc "github.com/openkcm/krypton/pkg/api/v1/proto/sealer"
	providergrpc "github.com/openkcm/krypton/pkg/api/v1/proto/test/provider"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestYOKLifecycle(t *testing.T) {
	env := setupRootWithTestProvider(t)
	ctx := t.Context()
	tenantClient := admingrpc.NewTenantServiceClient(env.conn)
	keyClient := keygrpc.NewKeyServiceClient(env.conn)
	providerClient := providergrpc.NewServiceClient(env.conn)
	sealerClient := sealergrpc.NewServiceClient(env.conn)
	keyVersionStore := newKeyVersionStore(t, env.db, storesql.Root)

	tenant := createYOKTenant(t, tenantClient)
	tenantID := tenant.GetId()
	rootKeyID := announceRootKey(t, keyClient, tenantID)
	homeDir := t.TempDir()
	loginNoAuth(t, homeDir)

	const (
		instanceID       = "external-instance"
		firstKeyID       = "external-key-1"
		secondKeyID      = "external-key-2"
		initialToken     = "initial-token"
		replacementToken = "replacement-token"
	)
	aad := []byte("yok lifecycle")
	var firstChildID string

	t.Run("bind", func(t *testing.T) {
		_, err := providerClient.UpsertInstance(ctx, &providergrpc.UpsertInstanceRequest{
			InstanceId: instanceID,
		})
		require.NoError(t, err)
		_, err = providerClient.UpsertKey(ctx, &providergrpc.UpsertKeyRequest{
			InstanceId: instanceID,
			KeyId:      firstKeyID,
		})
		require.NoError(t, err)
		_, err = providerClient.UpsertKeyAuth(ctx, &providergrpc.UpsertKeyAuthRequest{
			InstanceId:  instanceID,
			KeyId:       firstKeyID,
			AccessToken: initialToken,
		})
		require.NoError(t, err)

		cmd := newCLICommand(
			ctx,
			homeDir,
			"yok", "bind", "test-provider",
			"--tenant-id", tenantID,
			"--key-id", rootKeyID,
			"--instance-id", instanceID,
			"--provider-key-id", firstKeyID,
			"--access-token", initialToken,
			"--server", env.serverAddr,
		)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "bind failed: %s", output)

		versions, err := keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    rootKeyID,
		})
		require.NoError(t, err)
		require.Len(t, versions.KeyVersions, 1)
		assert.Equal(t, firstKeyID, versions.KeyVersions[0].Labels[sealer.ProviderKeyMetadataKey(providertest.TypeProviderTest)])

		activateKey(t, keyClient, tenantID, rootKeyID)
		firstChildID = announceAndActivateChildKey(t, keyClient, tenantID, rootKeyID)

		sealed, err := sealerClient.Seal(ctx, &sealergrpc.SealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Plaintext:  []byte("root secret"),
			Aad:        aad,
		})
		require.NoError(t, err)
		unsealed, err := sealerClient.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Ciphertext: sealed.GetCiphertext(),
			Aad:        aad,
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("root secret"), unsealed.GetPlaintext())
	})

	t.Run("rotate-auth", func(t *testing.T) {
		sealed, err := sealerClient.Seal(ctx, &sealergrpc.SealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Plaintext:  []byte("root secret"),
			Aad:        aad,
		})
		require.NoError(t, err, "bind must run first")

		_, err = providerClient.UpsertKeyAuth(ctx, &providergrpc.UpsertKeyAuthRequest{
			InstanceId:  instanceID,
			KeyId:       firstKeyID,
			AccessToken: replacementToken,
		})
		require.NoError(t, err)
		_, err = sealerClient.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Ciphertext: sealed.GetCiphertext(),
			Aad:        aad,
		})
		assert.Error(t, err)

		cmd := newCLICommand(
			ctx,
			homeDir,
			"yok", "rotate-auth", "test-provider",
			"--tenant-id", tenantID,
			"--key-id", rootKeyID,
			"--access-token", replacementToken,
			"--server", env.serverAddr,
		)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "authentication rotation failed: %s", output)

		unsealed, err := sealerClient.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Ciphertext: sealed.GetCiphertext(),
			Aad:        aad,
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("root secret"), unsealed.GetPlaintext())
	})

	t.Run("rotate-key", func(t *testing.T) {
		sealedV1, err := sealerClient.Seal(ctx, &sealergrpc.SealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Plaintext:  []byte("first secret"),
			Aad:        aad,
		})
		require.NoError(t, err, "rotate-auth must run first")

		_, err = providerClient.UpsertKey(ctx, &providergrpc.UpsertKeyRequest{
			InstanceId: instanceID,
			KeyId:      secondKeyID,
		})
		require.NoError(t, err)
		_, err = providerClient.UpsertKeyAuth(ctx, &providergrpc.UpsertKeyAuthRequest{
			InstanceId:  instanceID,
			KeyId:       secondKeyID,
			AccessToken: replacementToken,
		})
		require.NoError(t, err)

		cmd := newCLICommand(
			ctx,
			homeDir,
			"yok", "rotate-key", "test-provider",
			"--tenant-id", tenantID,
			"--key-id", rootKeyID,
			"--provider-key-id", secondKeyID,
			"--server", env.serverAddr,
		)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "key rotation failed: %s", output)

		versions, err := keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    rootKeyID,
		})
		require.NoError(t, err)
		require.Len(t, versions.KeyVersions, 2)
		providerKeys := make(map[int]string, len(versions.KeyVersions))
		for _, version := range versions.KeyVersions {
			label := sealer.ProviderKeyMetadataKey(providertest.TypeProviderTest)
			providerKeys[version.Version] = version.Labels[label]
		}
		assert.Equal(t, map[int]string{1: firstKeyID, 2: secondKeyID}, providerKeys)

		secondChildID := announceAndActivateChildKey(t, keyClient, tenantID, rootKeyID)
		firstChildVersions, err := keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    firstChildID,
		})
		require.NoError(t, err)
		require.Len(t, firstChildVersions.KeyVersions, 1)
		require.NotNil(t, firstChildVersions.KeyVersions[0].ParentKeyVersion)
		// Existing children remain wrapped by root key version 1. Once automatic
		// child resealing is implemented, this child should reference version 2.
		assert.Equal(t, 1, *firstChildVersions.KeyVersions[0].ParentKeyVersion)

		secondChildVersions, err := keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
			TenantID: tenantID,
			KeyID:    secondChildID,
		})
		require.NoError(t, err)
		require.Len(t, secondChildVersions.KeyVersions, 1)
		require.NotNil(t, secondChildVersions.KeyVersions[0].ParentKeyVersion)
		assert.Equal(t, 2, *secondChildVersions.KeyVersions[0].ParentKeyVersion)

		sealedV2, err := sealerClient.Seal(ctx, &sealergrpc.SealRequest{
			TenantId:   tenantID,
			KeyId:      secondChildID,
			KeyVersion: 1,
			Plaintext:  []byte("second secret"),
			Aad:        aad,
		})
		require.NoError(t, err)

		unsealedV1, err := sealerClient.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Ciphertext: sealedV1.GetCiphertext(),
			Aad:        aad,
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("first secret"), unsealedV1.GetPlaintext())

		unsealedV2, err := sealerClient.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   tenantID,
			KeyId:      secondChildID,
			KeyVersion: 1,
			Ciphertext: sealedV2.GetCiphertext(),
			Aad:        aad,
		})
		require.NoError(t, err)
		assert.Equal(t, []byte("second secret"), unsealedV2.GetPlaintext())
	})

	t.Run("unbind", func(t *testing.T) {
		sealed, err := sealerClient.Seal(ctx, &sealergrpc.SealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Plaintext:  []byte("first secret"),
			Aad:        aad,
		})
		require.NoError(t, err, "bind must run first")

		args := []string{
			"yok", "unbind",
			"--tenant-id", tenantID,
			"--key-id", rootKeyID,
			"--server", env.serverAddr,
		}
		cmd := newCLICommand(
			ctx,
			homeDir,
			args...,
		)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "unbind failed: %s", output)
		cmd = newCLICommand(ctx, homeDir, args...)
		output, err = cmd.CombinedOutput()
		require.NoError(t, err, "unbind should be idempotent: %s", output)

		_, err = sealerClient.Unseal(ctx, &sealergrpc.UnsealRequest{
			TenantId:   tenantID,
			KeyId:      firstChildID,
			KeyVersion: 1,
			Ciphertext: sealed.GetCiphertext(),
			Aad:        aad,
		})
		assert.Error(t, err)
	})
}

func TestYOKMissingBinding(t *testing.T) {
	env := setupRootWithTestProvider(t)
	ctx := t.Context()
	tenantClient := admingrpc.NewTenantServiceClient(env.conn)
	keyClient := keygrpc.NewKeyServiceClient(env.conn)
	keyStore := newKeyStore(t, env.db, storesql.Root)
	tenant := createYOKTenant(t, tenantClient)
	tenantID := tenant.GetId()
	rootKeyID := announceRootKey(t, keyClient, tenantID)
	require.NoError(t, keyStore.UpdateKeyLifeCycleState(ctx, store.UpdateKeyLifeCycleStateQuery{
		ID:       rootKeyID,
		TenantID: tenantID,
		NewState: model.KeyLifeCycleActive,
	}))

	homeDir := t.TempDir()
	loginNoAuth(t, homeDir)
	tests := []struct {
		name       string
		args       []string
		wantOutput string
	}{
		{
			name:       "rotate-auth",
			args:       []string{"yok", "rotate-auth", "test-provider", "--access-token", "replacement-token"},
			wantOutput: "failed to rotate test-provider authentication",
		},
		{
			name:       "rotate-key",
			args:       []string{"yok", "rotate-key", "test-provider", "--provider-key-id", "replacement-key"},
			wantOutput: "failed to rotate test-provider key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append(tt.args,
				"--tenant-id", tenantID,
				"--key-id", rootKeyID,
				"--server", env.serverAddr,
			)
			cmd := newCLICommand(ctx, homeDir, args...)
			output, err := cmd.CombinedOutput()
			assert.Error(t, err)
			assert.Contains(t, string(output), tt.wantOutput)
		})
	}
}

func TestYOKBindAcceptsUnprovisionedKey(t *testing.T) {
	env := setupRootWithTestProvider(t)
	ctx := t.Context()
	tenantClient := admingrpc.NewTenantServiceClient(env.conn)
	keyClient := keygrpc.NewKeyServiceClient(env.conn)
	keyVersionStore := newKeyVersionStore(t, env.db, storesql.Root)
	tenant := createYOKTenant(t, tenantClient)
	tenantID := tenant.GetId()
	rootKeyID := announceRootKey(t, keyClient, tenantID)
	homeDir := t.TempDir()
	loginNoAuth(t, homeDir)

	cmd := newCLICommand(
		ctx,
		homeDir,
		"yok", "bind", "test-provider",
		"--tenant-id", tenantID,
		"--key-id", rootKeyID,
		"--instance-id", "missing-instance",
		"--provider-key-id", "missing-key",
		"--access-token", "unused-token",
		"--server", env.serverAddr,
	)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "binding records external coordinates without contacting the provider: %s", output)

	versions, err := keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
		TenantID: tenantID,
		KeyID:    rootKeyID,
	})
	require.NoError(t, err)
	require.Len(t, versions.KeyVersions, 1)
	assert.Equal(t, "missing-key", versions.KeyVersions[0].Labels[sealer.ProviderKeyMetadataKey(providertest.TypeProviderTest)])
}

func TestYOKRequiredFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		flag string
	}{
		{name: "key-id", args: []string{"yok", "unbind", "--tenant-id", uuid.New().String()}, flag: "key-id"},
		{
			name: "instance-id",
			args: []string{
				"yok", "bind", "test-provider",
				"--key-id", uuid.New().String(),
				"--provider-key-id", "provider-key",
				"--access-token", "token",
			},
			flag: "instance-id",
		},
		{
			name: "access-token",
			args: []string{
				"yok", "rotate-auth", "test-provider",
				"--key-id", uuid.New().String(),
			},
			flag: "access-token",
		},
		{
			name: "provider-key-id",
			args: []string{
				"yok", "rotate-key", "test-provider",
				"--key-id", uuid.New().String(),
			},
			flag: "provider-key-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newCLICommand(t.Context(), t.TempDir(), tt.args...)
			output, err := cmd.CombinedOutput()
			assert.Error(t, err)
			assert.Contains(t, string(output), "required flag(s) \""+tt.flag+"\" not set")
		})
	}
}

type testEnvWithRootProvider struct {
	db         *sql.DB
	conn       *grpc.ClientConn
	serverAddr string
}

func setupRootWithTestProvider(t *testing.T) *testEnvWithRootProvider {
	t.Helper()
	db, connStr := createDatabase(t, storesql.Root)
	rootPort := freePort(t)
	configPath := writeSingleRootConfig(t, string(providertest.TypeProviderTest))
	rootBinary := buildBinary(t, "root", "../cmd/root")
	rootCmd := createCmd(t, rootBinary, []string{
		"ROOT_CONFIG_PATH=" + configPath,
		"DATABASE_URL=" + connStr,
		"SERVER_PORT=" + rootPort,
		providertest.EnableEnv + "=" + providertest.EnableAck,
		providertest.DirectoryEnv + "=" + t.TempDir(),
	})
	require.NoError(t, rootCmd.Start())
	waitForPort(t, rootPort)

	serverAddr := localAddress(rootPort)
	conn, err := grpc.NewClient(
		serverAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return &testEnvWithRootProvider{db: db, conn: conn, serverAddr: serverAddr}
}

func createYOKTenant(t *testing.T, client admingrpc.TenantServiceClient) *admingrpc.Tenant {
	t.Helper()
	response, err := client.CreateTenant(t.Context(), &admingrpc.CreateTenantRequest{
		Name: "yok-tenant-" + uuid.New().String(),
	})
	require.NoError(t, err)
	return response.GetTenant()
}

func announceRootKey(t *testing.T, client keygrpc.KeyServiceClient, tenantID string) string {
	t.Helper()
	response, err := client.AnnounceKey(t.Context(), &keygrpc.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     "K0",
		Name:     "root-key-" + uuid.New().String(),
	})
	require.NoError(t, err)
	keyID := response.GetKey().GetId()
	awaitKeyProcessingStatusViaGRPC(t, client, keyID, tenantID, string(model.KeyProcessingCompleted), 15*time.Second)
	return keyID
}

func announceAndActivateChildKey(
	t *testing.T,
	client keygrpc.KeyServiceClient,
	tenantID, rootKeyID string,
) string {
	t.Helper()
	response, err := client.AnnounceKey(t.Context(), &keygrpc.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     "K1",
		Name:     "child-key-" + uuid.New().String(),
		ParentId: rootKeyID,
	})
	require.NoError(t, err)
	keyID := response.GetKey().GetId()
	awaitKeyProcessingStatusViaGRPC(t, client, keyID, tenantID, string(model.KeyProcessingCompleted), 15*time.Second)
	activateKey(t, client, tenantID, keyID)
	return keyID
}

func activateKey(
	t *testing.T,
	client keygrpc.KeyServiceClient,
	tenantID, keyID string,
) {
	t.Helper()
	_, err := client.ActivateKey(t.Context(), &keygrpc.ActivateKeyRequest{
		TenantId: tenantID,
		Id:       keyID,
	})
	require.NoError(t, err)
	awaitKeyProcessingStatusViaGRPC(t, client, keyID, tenantID, string(model.KeyProcessingCompleted), 15*time.Second)
}
