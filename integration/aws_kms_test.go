package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/awskms"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/actions"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
	"github.com/openkcm/krypton/pkg/model"
)

func TestAWSKMSRootKey(t *testing.T) {
	t.Parallel()

	// given
	emulator := startAWSEmulator(t)
	keyARN := emulator.createKey(t)
	roleARN := emulator.createRole(t, keyARN)

	infra := startAWSKMSRoot(t, emulator.caPath)
	rootconn := grpcConn(t, infra.Find(t, regionRoot).listener.port)
	tCli := admin.NewTenantServiceClient(rootconn)
	rCli := rootkey.NewServiceClient(rootconn)
	kCli := keys.NewKeyServiceClient(rootconn)
	aCli := actions.NewActionServiceClient(rootconn)

	tenantID := createTenant(t, tCli, "tenant1")
	kmipRoot := infra.KMIPClient(t, regionRoot, tenantID)

	k0ID := announceAndWait(t, kCli, tenantID, "K0", "")
	createAWSKMSProvider(t, rCli, tenantID, k0ID, emulator, roleARN, keyARN)
	activateAndWait(t, kCli, aCli, tenantID, k0ID)

	// when
	k1ID := announceAndWait(t, kCli, tenantID, "K1", k0ID)
	activateAndWait(t, kCli, aCli, tenantID, k1ID)
	k2ID := announceAndWait(t, kCli, tenantID, "K2", k1ID)
	activateAndWait(t, kCli, aCli, tenantID, k2ID)

	// then
	assertKMIPKeyFound(t, kmipRoot, tenantID, k2ID)

	t.Run("should fail to read keys while the AWS KMS key is disabled", func(t *testing.T) {
		t.Parallel()

		// when
		emulator.disableKey(t, keyARN)

		// then
		assertKMIPKeyNotFound(t, kmipRoot, tenantID, k2ID)

		// when
		emulator.enableKey(t, keyARN)

		// then
		assertKMIPKeyFound(t, kmipRoot, tenantID, k2ID)
	})
}

func startAWSKMSRoot(t *testing.T, caPath string) services {
	t.Helper()
	c := &cleanupCollector{}
	t.Cleanup(func() { runCleanups(c.fns) })

	cfg := rootLevelConfig
	cfg.RootKey = &spec.RootKeySpec{
		AllowedProviders: []sealer.Type{awskms.TypeAwsKms},
		Vault:            rootLevelConfig.RootKey.Vault,
	}

	infra, err := initKRInfraServices(c, cfg, "SSL_CERT_FILE="+caPath)
	require.NoError(t, err)
	t.Cleanup(infra.Close)
	return infra
}

func createAWSKMSProvider(
	t *testing.T,
	rCli rootkey.ServiceClient,
	tenantID, keyID string,
	emulator awsEmulator,
	roleARN, keyARN string,
) {
	t.Helper()
	_, err := rCli.CreateProvider(t.Context(), &rootkey.CreateProviderRequest{
		TenantId: tenantID,
		KeyId:    keyID,
		Provider: &rootkey.Provider{Provider: &rootkey.Provider_AwsKms{
			AwsKms: &rootkey.AwsKmsProvider{
				Config: &rootkey.AwsKmsConfig{
					Region:      emulatorRegion,
					KmsEndpoint: emulator.endpoint,
					StsEndpoint: emulator.endpoint,
				},
				Auth: &rootkey.AwsKmsAuth{
					RoleArn: roleARN,
					CredentialSource: &rootkey.AwsKmsAuth_Static{Static: &rootkey.AwsStaticCredentials{
						AccessKeyId:     emulator.accessKey,
						SecretAccessKey: emulator.secretKey,
					}},
				},
				ProviderKey: &rootkey.AwsKmsKey{KeyArn: keyARN},
			},
		}},
	})
	require.NoError(t, err)
}

func announceAndWait(t *testing.T, kCli keys.KeyServiceClient, tenantID, kind, parentID string) string {
	t.Helper()
	keyID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     kind,
		Name:     keyName(regionRoot),
		ParentId: parentID,
	})
	assertKeyStateAndStatus(t, kCli, tenantID, keyID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
	return keyID
}

func activateAndWait(
	t *testing.T,
	kCli keys.KeyServiceClient,
	aCli actions.ActionServiceClient,
	tenantID, keyID string,
) {
	t.Helper()
	jobID := activateKey(t, kCli, tenantID, keyID, false)
	isJobFinished(t, aCli, jobID)
	assertKeyStateAndStatus(t, kCli, tenantID, keyID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
}
