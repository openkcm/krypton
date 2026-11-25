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

// TestCompromiseKey_RegionLevel validates key compromise in a two-level
// hierarchy: root manages K0-K1, agents (ap, eu) manage K2-K3.
//
//	           root
//	      [k0(root) k1(kek)]
//	        /            \
//	       /              \
//	      ap              eu
//	[k2(tek) k3(dek)]   [k2(tek) k3(dek)]
func TestCompromiseKey_RegionLevel(t *testing.T) {
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

	// Compromise keys individually across ap and eu, verify KMIP isolation.
	t.Run("should compromise keys individually across all regions", func(t *testing.T) {
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

		jobID = activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		assertKMIPKeyFound(t, kmipAp, tenantID, k3apID)
		assertKMIPKeyFound(t, kmipEu, tenantID, k3euID)

		jobID = compromiseKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k2euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k2apID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k3euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k3apID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})

	// Compromise k1 individually, then cascade-compromise all children via CLI binary.
	t.Run("should compromise key hierarchy via cli", func(t *testing.T) {
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

		jobID = activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		compromiseKeyCli(t, homeDir, rootsrv.listener.port, tenantID, k1rootID, false)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		compromiseKeyCli(t, homeDir, rootsrv.listener.port, tenantID, k1rootID, true)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})
	// Cascading compromise from k1 should compromise all children (ap + eu).
	t.Run("should do cascading compromise for all regions", func(t *testing.T) {
		t.Parallel()
		// announcing a kek key in root
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

		jobID = compromiseKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})

	// Activate -> Suspend -> Compromise cycle via cascading.
	t.Run("should cascading compromise suspended keys", func(t *testing.T) {
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

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// suspending all keys
		jobID = suspendKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)

		// compromising all keys
		jobID = compromiseKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})

	t.Run("should cascading compromise deactivate keys", func(t *testing.T) {
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

		jobID := activateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

		// deactivating all keys
		jobID = deactivateKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleDeactivated, model.KeyProcessingCompleted)

		// compromising all keys
		jobID = compromiseKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})
	// Compromising pre-activation keys should mark them as compromised.
	t.Run("should compromise all announced key", func(t *testing.T) {
		t.Parallel()
		// announcing keys under root
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

		jobID := compromiseKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})

	// Compromise with a non-existent key ID should return an error.
	t.Run("should fail if compromise for unknown key", func(t *testing.T) {
		t.Parallel()

		// compromising an unknown key should fail
		_, err := kCli.CompromiseKey(t.Context(), &keys.CompromiseKeyRequest{
			Id:        uuid.New().String(),
			TenantId:  tenantID,
			Cascading: false,
		})
		assert.Error(t, err, "expected error when compromise unknown key")
	})

	// Compromise with a non-existent tenant ID should return an error.
	t.Run("should fail if compromise for unknown tenantID", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		// compromising with unknown tenant should fail
		_, err := kCli.CompromiseKey(t.Context(), &keys.CompromiseKeyRequest{
			Id:        k1rootID,
			TenantId:  uuid.New().String(),
			Cascading: false,
		})
		assert.Error(t, err, "expected error when compromise unknown key")
	})
}

// TestCompromiseKey_RootLevel validates key compromise in a single-node
// hierarchy where root manages all key kinds (K0-K2).
//
//	     root
//	[k0(root) k1(tek) k2(dek)]
func TestCompromiseKey_RootLevel(t *testing.T) {
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

	// Compromise each key individually down the hierarchy.
	t.Run("should compromise all keys in region", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := compromiseKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		k2rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K2",
			Name:     keyName(regionRoot),
			ParentId: k1rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k2rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})

	// Cascading compromise from k1 should compromise all descendants.
	t.Run("should do cascading compromise all keys in region", func(t *testing.T) {
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

		jobID := compromiseKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})
}

// TestCompromiseKey_CountryLevel validates key compromise in a three-level
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
func TestCompromiseKey_CountryLevel(t *testing.T) {
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

	// Compromise each key individually from root down to country level (de).
	t.Run("should compromise all keys in germany", func(t *testing.T) {
		t.Parallel()
		k1rootID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId: tenantID,
			Kind:     "K1",
			Name:     keyName(regionRoot),
			ParentId: k0rootID,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID := compromiseKey(t, kCli, tenantID, k1rootID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		k2euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K2",
			Name:       keyName(regionEu),
			ParentId:   k1rootID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k2euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		k3euID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K3",
			Name:       keyName(regionEu),
			ParentId:   k2euID,
			TargetName: regionEu,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k3euID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		k4deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K4",
			Name:       keyName(regionGermany),
			ParentId:   k3euID,
			TargetName: regionGermany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k4deID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		k5deID := announceKey(t, kCli, &keys.AnnounceKeyRequest{
			TenantId:   tenantID,
			Kind:       "K5",
			Name:       keyName(regionGermany),
			ParentId:   k4deID,
			TargetName: regionGermany,
		})
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCyclePreActivation, model.KeyProcessingCompleted)

		jobID = compromiseKey(t, kCli, tenantID, k5deID, false)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
	})

	// Cascading compromise from k1 should propagate through all regions and countries.
	t.Run("should do cascading compromise on all regions", func(t *testing.T) {
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

		jobID := compromiseKey(t, kCli, tenantID, k1rootID, true)
		isJobFinished(t, aCli, jobID)
		assertKeyStateAndStatus(t, kCli, tenantID, k1rootID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k2apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3euID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k3apID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4deID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4esID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4jpID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k4sgID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5deID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5esID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5jpID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)
		assertKeyStateAndStatus(t, kCli, tenantID, k5sgID, model.KeyLifeCycleCompromised, model.KeyProcessingCompleted)

		assertKMIPKeyNotFound(t, kmipGermany, tenantID, k5deID)
		assertKMIPKeyNotFound(t, kmipSpain, tenantID, k5esID)
		assertKMIPKeyNotFound(t, kmipJapan, tenantID, k5jpID)
		assertKMIPKeyNotFound(t, kmipSingapore, tenantID, k5sgID)
	})
}
