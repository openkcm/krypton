package integration

import (
	"testing"
	"time"
	"uuid"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/actions"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
	"github.com/openkcm/krypton/pkg/api/v1/proto/test/provider"
	"github.com/openkcm/krypton/pkg/model"
)

// TestActivateKey_RegionLevel validates key activation in a two-level
// hierarchy: root manages K0-K1, agents (ap, eu) manage K2-K3.
func TestActivateKey_RegionLevel(t *testing.T) {
	//                root
	//           [k0(root) k1(kek)]
	//             /            \
	//            /              \
	//           ap              eu
	//     [k2(tek) k3(dek)]   [k2(tek) k3(dek)]

	infras := buildKRInfraServices(t, regionLevelConfig)
	t.Cleanup(func() {
		infras.Close()
	})

	rootsrv := infras.Find(t, region_root)
	rootconn := grpcConn(t, rootsrv.port)

	tCli := admin.NewTenantServiceClient(rootconn)
	rCli := rootkey.NewServiceClient(rootconn)
	pCli := provider.NewServiceClient(rootconn)
	kCli := keys.NewKeyServiceClient(rootconn)
	aCli := actions.NewActionServiceClient(rootconn)

	// creating a tenant in root
	tenantID := createTenant(t, tCli, "tenant1")

	homeDir := t.TempDir()
	// login with no auth
	loginNoAuth(t, homeDir)

	// announcing a key in root
	k0rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     "K0",
		Name:     keyName(region_root),
		ParentId: "",
	})
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

	// create a provider for the root key in root
	createProviderAndBind(t, rCli, pCli, tenantID, k0rootID)

	// activating the root key in root
	jobID := activateKey(t, kCli, tenantID, k0rootID, false)
	isJobFinished(t, aCli, jobID, 15*time.Second)
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

	// Activate keys individually across ap and eu, verify KMIP isolation.
	t.Run("should activate keys individually across all regions", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1rootID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k2apID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_ap),
			ParentId:   k2apID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k3apID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k2euID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_eu),
			ParentId:   k2euID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k3euID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, infras, region_ap, tenantID, k3apID)
		assertKMIPKeyFound(t, infras, region_eu, tenantID, k3euID)

		assertKMIPKeyNotFound(t, infras, region_eu, tenantID, k3apID)
		assertKMIPKeyNotFound(t, infras, region_ap, tenantID, k3euID)
	})

	// Activate k1 individually, then cascade-activate all children via CLI binary.
	t.Run("should activate key hierarchy via cli", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// activate k1 individually (non-cascading) via CLI
		jobID = activateKeyCli(t, homeDir, rootsrv.port, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1rootID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_ap),
			ParentId:   k2apID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_eu),
			ParentId:   k2euID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// cascade-activate all children from k1 via CLI
		jobID = activateKeyCli(t, homeDir, rootsrv.port, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, infras, region_ap, tenantID, k3apID)
		assertKMIPKeyFound(t, infras, region_eu, tenantID, k3euID)

		assertKMIPKeyNotFound(t, infras, region_eu, tenantID, k3apID)
		assertKMIPKeyNotFound(t, infras, region_ap, tenantID, k3euID)
	})
	// Cascading activate from k1 should activate all children (ap + eu).
	t.Run("should do cascading activation for all regions", func(t *testing.T) {
		// announcing a kek key in root
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1rootID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_eu),
			ParentId:   k2euID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_ap),
			ParentId:   k2apID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, infras, region_ap, tenantID, k3apID)
		assertKMIPKeyFound(t, infras, region_eu, tenantID, k3euID)

		assertKMIPKeyNotFound(t, infras, region_eu, tenantID, k3apID)
		assertKMIPKeyNotFound(t, infras, region_ap, tenantID, k3euID)
	})

	// Activate -> Suspend -> Reactivate cycle via cascading.
	t.Run("should cascading reactivate suspended keys", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1rootID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_eu),
			ParentId:   k2euID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_ap),
			ParentId:   k2apID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// suspending all keys in eu region
		jobID = suspendKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

		// reactivating all keys in eu region
		jobID = activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
	})

	// Verify KMIP secrets remain the same after suspend/reactivate cycle.
	t.Run("should not create a new secret while reactivating a key", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1rootID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_eu),
			ParentId:   k2euID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_ap),
			ParentId:   k2apID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k3eubefore := assertKMIPKeyFound(t, infras, region_eu, tenantID, k3euID)
		k3apbefore := assertKMIPKeyFound(t, infras, region_ap, tenantID, k3apID)

		// suspending all keys in eu region
		jobID = suspendKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

		// reactivating all keys in eu region
		jobID = activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k3euafter := assertKMIPKeyFound(t, infras, region_eu, tenantID, k3euID)
		k3apafter := assertKMIPKeyFound(t, infras, region_ap, tenantID, k3apID)

		assert.Equal(t, k3eubefore, k3euafter, "expected the same secret to be used after reactivation")
		assert.Equal(t, k3apbefore, k3apafter, "expected the same secret to be used after reactivation")
		assert.NotEqual(t, k3eubefore, k3apbefore, "expected different secrets for different regions")
	})

	// Child key cannot be activated when its parent is suspended.
	t.Run("should not activate a key if a parent is not in active state", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1rootID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// suspending all keys in eu region from k1
		jobID = suspendKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

		// activating a child below the k1
		_, err := kCli.ActivateKey(t.Context(), &keys.ActivateKeyRequest{
			Id:        k2euID,
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when activating a key with a suspended parent")
	})

	// Deactivated keys are terminal and cannot be reactivated.
	t.Run("should not activate deactivated key", func(t *testing.T) {
		// announcing keys under root
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1rootID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		_, err := kCli.ActivateKey(t.Context(), &keys.ActivateKeyRequest{
			Id:        k1rootID,
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when activating deactivated key")
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})

	// Compromised keys are terminal and cannot be reactivated.
	t.Run("should not activate compromised key", func(t *testing.T) {
		// announcing keys under root
		k1KeyID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1KeyID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1KeyID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1KeyID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1KeyID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1KeyID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k1KeyID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1KeyID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		_, err := kCli.ActivateKey(t.Context(), &keys.ActivateKeyRequest{
			Id:        k1KeyID,
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when activating compromised key")
		assertKeyStateAndStatus(t, kCli, tenantID, k1KeyID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})

	// Activation with a non-existent key ID should return an error.
	t.Run("should fail if activated for unknown key", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// activating an unknown key should fail
		_, err := kCli.ActivateKey(t.Context(), &keys.ActivateKeyRequest{
			Id:        uuid.New().String(),
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when activating unknown key")
	})

	// Activation with a non-existent tenant ID should return an error.
	t.Run("should fail if activated for unknown tenantID", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// activating an unknown key should fail
		_, err := kCli.ActivateKey(t.Context(), &keys.ActivateKeyRequest{
			Id:        k1rootID,
			TenantId:  uuid.New().String(),
			Cascading: false,
		})
		assert.Error(t, err, "expected error when activating unknown key")
	})
}

// TestActivateKey_RootLevel validates key activation in a single-node
// hierarchy where root manages all key kinds (K0-K2).
func TestActivateKey_RootLevel(t *testing.T) {
	//       root
	//  [k0(root) k1(tek) k2(dek)]

	infras := buildKRInfraServices(t, rootLevelConfig)
	t.Cleanup(func() {
		infras.Close()
	})

	rootsrv := infras.Find(t, region_root)
	rootconn := grpcConn(t, rootsrv.port)

	tCli := admin.NewTenantServiceClient(rootconn)
	rCli := rootkey.NewServiceClient(rootconn)
	pCli := provider.NewServiceClient(rootconn)
	kCli := keys.NewKeyServiceClient(rootconn)
	aCli := actions.NewActionServiceClient(rootconn)

	// creating a tenant in root
	tenantID := createTenant(t, tCli, "tenant1")

	// announcing a key in root
	k0rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     "K0",
		Name:     keyName(region_root),
		ParentId: "",
	})
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

	// create a provider for the root key in root
	createProviderAndBind(t, rCli, pCli, tenantID, k0rootID)

	// activating the root key in root
	jobID := activateKey(t, kCli, tenantID, k0rootID, false)
	isJobFinished(t, aCli, jobID, 15*time.Second)
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

	// Activate each key individually down the hierarchy.
	t.Run("should activate all keys in region", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K2",
			Name:     keyName(region_root),
			ParentId: k1rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k2rootID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, infras, region_root, tenantID, k2rootID)
	})

	// Cascading activate from k1 should activate all descendants.
	t.Run("should do cascading activation all keys in region", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K2",
			Name:     keyName(region_root),
			ParentId: k1rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, infras, region_root, tenantID, k2rootID)
	})
}

// TestActivateKey_CountryLevel validates key activation in a three-level
// hierarchy: root -> region (eu, ap) -> country (de, es, jp, sg).
func TestActivateKey_CountryLevel(t *testing.T) {
	//                       root
	//                  [k0(root) k1(kek)]
	//                    /            \
	//                   /              \
	//                  eu              ap
	//            [k2(tek) k3(kek)]    [k2(tek) k3(kek)]
	//              /        \            /         \
	//             /          \          /           \
	//            de          es        jp           sg
	//      [k4(tek) k5(dek)]    [k4(tek) k5(dek)]

	infras := buildKRInfraServices(t, countryLevelConfig)
	t.Cleanup(func() {
		infras.Close()
	})

	rootsrv := infras.Find(t, region_root)
	rootconn := grpcConn(t, rootsrv.port)

	tCli := admin.NewTenantServiceClient(rootconn)
	rCli := rootkey.NewServiceClient(rootconn)
	pCli := provider.NewServiceClient(rootconn)
	kCli := keys.NewKeyServiceClient(rootconn)
	aCli := actions.NewActionServiceClient(rootconn)

	// creating a tenant in root
	tenantID := createTenant(t, tCli, "tenant1")

	// announcing a key in root
	k0rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     "K0",
		Name:     keyName(region_root),
		ParentId: "",
	})
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

	// create a provider for the root key in root
	createProviderAndBind(t, rCli, pCli, tenantID, k0rootID)

	// activating the root key in root
	jobID := activateKey(t, kCli, tenantID, k0rootID, false)
	isJobFinished(t, aCli, jobID, 15*time.Second)
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

	// Activate each key individually from root down to country level (de).
	t.Run("should activate all keys in germany", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k2euID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_eu),
			ParentId:   k2euID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k3euID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k4deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(region_germany),
			ParentId:   k3euID,
			TargetName: region_germany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k4deID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k5deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(region_germany),
			ParentId:   k4deID,
			TargetName: region_germany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k5deID, false)
		isJobFinished(t, aCli, jobID, 15*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, infras, region_germany, tenantID, k5deID)
		// TODO: bug here as we should not expose DEK
		assertKMIPKeyFound(t, infras, region_germany, tenantID, k4deID)
	})

	// Cascading activate from k1 should propagate through all regions and countries.
	t.Run("should do cascading activation on all regions", func(t *testing.T) {
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(region_root),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_eu),
			ParentId:   k1rootID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_eu),
			ParentId:   k2euID,
			TargetName: region_eu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k4deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(region_germany),
			ParentId:   k3euID,
			TargetName: region_germany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k5deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(region_germany),
			ParentId:   k4deID,
			TargetName: region_germany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k4esID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(region_spain),
			ParentId:   k3euID,
			TargetName: region_spain,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4esID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k5esID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(region_spain),
			ParentId:   k4esID,
			TargetName: region_spain,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5esID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(region_ap),
			ParentId:   k1rootID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(region_ap),
			ParentId:   k2apID,
			TargetName: region_ap,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k4jpID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(region_japan),
			ParentId:   k3apID,
			TargetName: region_japan,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4jpID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k5jpID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(region_japan),
			ParentId:   k4jpID,
			TargetName: region_japan,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5jpID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k4sgID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(region_singapore),
			ParentId:   k3apID,
			TargetName: region_singapore,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4sgID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k5sgID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(region_singapore),
			ParentId:   k4sgID,
			TargetName: region_singapore,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5sgID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID, 20*time.Second)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4esID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4jpID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4sgID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5esID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5jpID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5sgID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, infras, region_germany, tenantID, k5deID)
		assertKMIPKeyFound(t, infras, region_spain, tenantID, k5esID)
		assertKMIPKeyFound(t, infras, region_japan, tenantID, k5jpID)
		assertKMIPKeyFound(t, infras, region_singapore, tenantID, k5sgID)

		// TODO: bug here as we should not expose TEK
		assertKMIPKeyFound(t, infras, region_germany, tenantID, k4deID)
	})
}
