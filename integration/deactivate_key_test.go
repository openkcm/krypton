package integration

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/actions"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
	"github.com/openkcm/krypton/pkg/api/v1/proto/test/provider"
	"github.com/openkcm/krypton/pkg/model"
)

// TestDeactivateKey_RegionLevel validates key deactivation in a two-level
// hierarchy: root manages K0-K1, agents (ap, eu) manage K2-K3.
//
// Valid transitions to Deactivated: Active, Suspended.
// Invalid transitions: Pre-activation, Compromised, Destroyed (and already Deactivated+Completed).
//
//	           root
//	      [k0(root) k1(kek)]
//	        /            \
//	       /              \
//	      ap              eu
//	[k2(tek) k3(dek)]   [k2(tek) k3(dek)]
func TestDeactivateKey_RegionLevel(t *testing.T) {
	t.Parallel()
	rootsrv := regionLevelInfra.Find(t, regionRoot)
	rootconn := grpcConn(t, rootsrv.listener.port)

	tCli := admin.NewTenantServiceClient(rootconn)
	rCli := rootkey.NewServiceClient(rootconn)
	pCli := provider.NewServiceClient(rootconn)
	kCli := keys.NewKeyServiceClient(rootconn)
	aCli := actions.NewActionServiceClient(rootconn)

	// creating a tenant in root
	tenantID := createTenant(t, tCli, "tenant1")

	kmipAp := regionLevelInfra.KMIPClient(t, regionAp, tenantID)
	kmipEu := regionLevelInfra.KMIPClient(t, regionEu, tenantID)

	homeDir := t.TempDir()
	// login with no auth
	loginNoAuth(t, homeDir)

	// announcing a key in root
	k0rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     "K0",
		Name:     keyName(regionRoot),
		ParentId: "",
	})
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

	// create a provider for the root key in root
	createProviderAndBind(t, rCli, pCli, tenantID, k0rootID)

	// activating the root key in root
	jobID := activateKey(t, kCli, tenantID, k0rootID, false)
	isJobFinished(t, aCli, jobID)
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

	// Deactivate keys individually across ap and eu, verify KMIP isolation.
	t.Run("should deactivate keys individually across all regions", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionAp),
			ParentId:   k1rootID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k2apID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionAp),
			ParentId:   k2apID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k3apID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1rootID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k2euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionEu),
			ParentId:   k2euID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k3euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, kmipAp, tenantID, k3apID)
		assertKMIPKeyFound(t, kmipEu, tenantID, k3euID)

		// deactivate keys individually bottom-up
		jobID = deactivateKey(t, kCli, tenantID, k3apID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k3euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k2apID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k2euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})

	// Deactivate k1 individually, then cascade-deactivate all children via CLI binary.
	t.Run("should deactivate key hierarchy via cli", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// activate all keys first via cascading
		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionAp),
			ParentId:   k1rootID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionAp),
			ParentId:   k2apID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1rootID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionEu),
			ParentId:   k2euID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// cascade-activate all from k1
		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// deactivate k1 individually (non-cascading) via CLI
		jobID = deactivateKeyCli(t, homeDir, rootsrv.listener.port, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		// cascade-deactivate all children from k1 via CLI
		// k1 is already deactivated+completed, but children should still be deactivated
		jobID = deactivateKeyCli(t, homeDir, rootsrv.listener.port, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})

	// Cascading deactivate from k1 should deactivate all children (ap + eu).
	t.Run("should do cascading deactivation for all regions", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionAp),
			ParentId:   k1rootID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1rootID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionEu),
			ParentId:   k2euID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionAp),
			ParentId:   k2apID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// cascade-activate all from k1
		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, kmipAp, tenantID, k3apID)
		assertKMIPKeyFound(t, kmipEu, tenantID, k3euID)

		assertKMIPKeyNotFound(t, kmipEu, tenantID, k3apID)
		assertKMIPKeyNotFound(t, kmipAp, tenantID, k3euID)

		// cascade-deactivate all from k1
		jobID = deactivateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})

	// Activate -> Suspend -> Deactivate cycle via cascading.
	t.Run("should cascading deactivate suspended keys", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionAp),
			ParentId:   k1rootID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1rootID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionEu),
			ParentId:   k2euID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionAp),
			ParentId:   k2apID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// activate all keys
		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// suspending all keys from k1
		jobID = suspendKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

		// deactivating all suspended keys from k1
		jobID = deactivateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})

	// Pre-activation keys cannot be deactivated (not yet active).
	t.Run("should not deactivate a pre-activation key", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// deactivating a pre-activation key should fail
		_, err := kCli.DeactivateKey(t.Context(), &keys.DeactivateKeyRequest{
			Id:        k1rootID,
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when deactivating a pre-activation key")
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)
	})

	// Deactivated keys are terminal and cannot be deactivated again.
	t.Run("should not deactivate an already deactivated key", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionAp),
			ParentId:   k1rootID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1rootID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		// deactivating again should fail
		_, err := kCli.DeactivateKey(t.Context(), &keys.DeactivateKeyRequest{
			Id:        k1rootID,
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when deactivating an already deactivated key")
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})

	// Compromised keys are terminal and cannot be deactivated.
	t.Run("should not deactivate compromised key", func(t *testing.T) {
		t.Parallel()
		k1KeyID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1KeyID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionAp),
			ParentId:   k1KeyID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1KeyID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1KeyID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1KeyID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k1KeyID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1KeyID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		_, err := kCli.DeactivateKey(t.Context(), &keys.DeactivateKeyRequest{
			Id:        k1KeyID,
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when deactivating compromised key")
		assertKeyStateAndStatus(t, kCli, tenantID, k1KeyID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})

	// Deactivation with a non-existent key ID should return an error.
	t.Run("should fail if deactivated for unknown key", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// deactivating an unknown key should fail
		_, err := kCli.DeactivateKey(t.Context(), &keys.DeactivateKeyRequest{
			Id:        uuid.New().String(),
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when deactivating unknown key")
	})

	// Deactivation with a non-existent tenant ID should return an error.
	t.Run("should fail if deactivated for unknown tenantID", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// deactivating with an unknown tenant should fail
		_, err := kCli.DeactivateKey(t.Context(), &keys.DeactivateKeyRequest{
			Id:        k1rootID,
			TenantId:  uuid.New().String(),
			Cascading: false,
		})
		assert.Error(t, err, "expected error when deactivating with unknown tenantID")
	})
}

// TestDeactivateKey_RootLevel validates key deactivation in a single-node
// hierarchy where root manages all key kinds (K0-K2).
//
//	     root
//	[k0(root) k1(tek) k2(dek)]
func TestDeactivateKey_RootLevel(t *testing.T) {
	t.Parallel()
	rootsrv := rootLevelInfra.Find(t, regionRoot)
	rootconn := grpcConn(t, rootsrv.listener.port)

	tCli := admin.NewTenantServiceClient(rootconn)
	rCli := rootkey.NewServiceClient(rootconn)
	pCli := provider.NewServiceClient(rootconn)
	kCli := keys.NewKeyServiceClient(rootconn)
	aCli := actions.NewActionServiceClient(rootconn)

	// creating a tenant in root
	tenantID := createTenant(t, tCli, "tenant1")

	kmipRoot := rootLevelInfra.KMIPClient(t, regionRoot, tenantID)

	// announcing a key in root
	k0rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     "K0",
		Name:     keyName(regionRoot),
		ParentId: "",
	})
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

	// create a provider for the root key in root
	createProviderAndBind(t, rCli, pCli, tenantID, k0rootID)

	// activating the root key in root
	jobID := activateKey(t, kCli, tenantID, k0rootID, false)
	isJobFinished(t, aCli, jobID)
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

	// Deactivate each key individually down the hierarchy.
	t.Run("should deactivate all keys in region", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K2",
			Name:     keyName(regionRoot),
			ParentId: k1rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k2rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, kmipRoot, tenantID, k2rootID)

		// deactivate bottom-up
		jobID = deactivateKey(t, kCli, tenantID, k2rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})

	// Cascading deactivate from k1 should deactivate all descendants.
	t.Run("should do cascading deactivation all keys in region", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K2",
			Name:     keyName(regionRoot),
			ParentId: k1rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// activate all first
		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, kmipRoot, tenantID, k2rootID)

		// cascade-deactivate all from k1
		jobID = deactivateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})
}

// TestDeactivateKey_CountryLevel validates key deactivation in a three-level
// hierarchy: root -> region (eu, ap) -> country (de, es, jp, sg).
//
//	                 root
//	            [k0(root) k1(kek)]
//	              /            \
//	             /              \
//	            eu              ap
//	      [k2(tek) k3(kek)]    [k2(tek) k3(kek)]
//	        /        \            /         \
//	       /          \          /           \
//	      de          es        jp           sg
//	[k4(tek) k5(dek)]    [k4(tek) k5(dek)]
func TestDeactivateKey_CountryLevel(t *testing.T) {
	t.Parallel()
	rootsrv := countryLevelInfra.Find(t, regionRoot)
	rootconn := grpcConn(t, rootsrv.listener.port)

	tCli := admin.NewTenantServiceClient(rootconn)
	rCli := rootkey.NewServiceClient(rootconn)
	pCli := provider.NewServiceClient(rootconn)
	kCli := keys.NewKeyServiceClient(rootconn)
	aCli := actions.NewActionServiceClient(rootconn)

	// creating a tenant in root
	tenantID := createTenant(t, tCli, "tenant1")

	kmipGermany := countryLevelInfra.KMIPClient(t, regionGermany, tenantID)
	kmipSpain := countryLevelInfra.KMIPClient(t, regionSpain, tenantID)
	kmipJapan := countryLevelInfra.KMIPClient(t, regionJapan, tenantID)
	kmipSingapore := countryLevelInfra.KMIPClient(t, regionSingapore, tenantID)

	// announcing a key in root
	k0rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
		TenantId: tenantID,
		Kind:     "K0",
		Name:     keyName(regionRoot),
		ParentId: "",
	})
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

	// create a provider for the root key in root
	createProviderAndBind(t, rCli, pCli, tenantID, k0rootID)

	// activating the root key in root
	jobID := activateKey(t, kCli, tenantID, k0rootID, false)
	isJobFinished(t, aCli, jobID)
	assertKeyStateAndStatus(t, kCli, tenantID, k0rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

	// Deactivate each key individually from root down to country level (de).
	t.Run("should deactivate all keys in germany", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := activateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1rootID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k2euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionEu),
			ParentId:   k2euID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k3euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k4deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(regionGermany),
			ParentId:   k3euID,
			TargetName: regionGermany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k4deID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		k5deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(regionGermany),
			ParentId:   k4deID,
			TargetName: regionGermany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = activateKey(t, kCli, tenantID, k5deID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, kmipGermany, tenantID, k5deID)
		assertKMIPKeyFound(t, kmipGermany, tenantID, k4deID)

		// deactivate bottom-up
		jobID = deactivateKey(t, kCli, tenantID, k5deID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k4deID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k3euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k2euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		jobID = deactivateKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})

	// Cascading deactivate from k1 should propagate through all regions and countries.
	t.Run("should do cascading deactivation on all regions", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1rootID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionEu),
			ParentId:   k2euID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k4deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(regionGermany),
			ParentId:   k3euID,
			TargetName: regionGermany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k5deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(regionGermany),
			ParentId:   k4deID,
			TargetName: regionGermany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k4esID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(regionSpain),
			ParentId:   k3euID,
			TargetName: regionSpain,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4esID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k5esID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(regionSpain),
			ParentId:   k4esID,
			TargetName: regionSpain,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5esID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k2apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionAp),
			ParentId:   k1rootID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k3apID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionAp),
			ParentId:   k2apID,
			TargetName: regionAp,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k4jpID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(regionJapan),
			ParentId:   k3apID,
			TargetName: regionJapan,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4jpID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k5jpID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(regionJapan),
			ParentId:   k4jpID,
			TargetName: regionJapan,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5jpID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k4sgID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(regionSingapore),
			ParentId:   k3apID,
			TargetName: regionSingapore,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4sgID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		k5sgID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(regionSingapore),
			ParentId:   k4sgID,
			TargetName: regionSingapore,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5sgID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// cascade-activate all from k1
		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
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

		assertKMIPKeyFound(t, kmipGermany, tenantID, k5deID)
		assertKMIPKeyFound(t, kmipSpain, tenantID, k5esID)
		assertKMIPKeyFound(t, kmipJapan, tenantID, k5jpID)
		assertKMIPKeyFound(t, kmipSingapore, tenantID, k5sgID)

		// cascade-deactivate all from k1
		jobID = deactivateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4esID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4jpID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4sgID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5esID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5jpID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5sgID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
	})
}
