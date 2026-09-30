package activatekey_test

import (
	"encoding/json/v2"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler/activatekey"
)

const testLocalTarget = "krypton-embedded"

func layerJob(t *testing.T, tenantID, rootKeyID string, keyIDs ...string) orbital.Job {
	t.Helper()
	data, err := json.Marshal(activatekey.LayerData{
		TenantID:  tenantID,
		RootKeyID: rootKeyID,
		KeyIDs:    keyIDs,
	})
	require.NoError(t, err)
	return orbital.Job{ID: uuid.NewV7(), Type: activatekey.JobType, Data: data}
}

func TestJobHandler_JobType(t *testing.T) {
	h := activatekey.NewJobHandler(nil, testLocalTarget)
	assert.Equal(t, activatekey.JobType, h.JobType())
}

func TestJobHandler_ConfirmJob(t *testing.T) {
	completeType := orbital.CompleteJobConfirmer().Type()
	continueType := orbital.ContinueJobConfirmer().Type()
	cancelType := orbital.CancelJobConfirmer("").Type()

	t.Run("confirms once every key in the layer exists", func(t *testing.T) {
		db := newRootDB(t)
		s := newStores(t, db)
		tenant := seedTenant(t, s.tenantStore)
		k0 := seedKey(t, s.keyStore, tenant.ID, "k0", "K0", testRootName, nil)

		h := activatekey.NewJobHandler(s.keyStore, testLocalTarget)
		res, err := h.ConfirmJob(t.Context(), layerJob(t, tenant.ID, k0.ID, k0.ID))
		require.NoError(t, err)
		assert.Equal(t, completeType, res.Type())
	})

	t.Run("keeps waiting when a key is not yet present", func(t *testing.T) {
		db := newRootDB(t)
		s := newStores(t, db)
		tenant := seedTenant(t, s.tenantStore)

		h := activatekey.NewJobHandler(s.keyStore, testLocalTarget)
		res, err := h.ConfirmJob(t.Context(), layerJob(t, tenant.ID, uuid.New().String(), uuid.New().String()))
		require.NoError(t, err)
		assert.Equal(t, continueType, res.Type())
	})

	t.Run("cancels on corrupt job data", func(t *testing.T) {
		h := activatekey.NewJobHandler(nil, testLocalTarget)
		res, err := h.ConfirmJob(t.Context(), orbital.Job{Type: activatekey.JobType, Data: []byte("not-json")})
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())
	})
}

func TestJobHandler_ResolveTasks(t *testing.T) {
	completeType := orbital.CompleteTaskResolver().Type()
	cancelType := orbital.CancelTaskResolver("").Type()

	t.Run("resolves the layer's keys into tasks", func(t *testing.T) {
		h := activatekey.NewJobHandler(nil, testLocalTarget)
		res, err := h.ResolveTasks(t.Context(), layerJob(t, "tenant", "root", "a", "b"), "")
		require.NoError(t, err)
		assert.Equal(t, completeType, res.Type())
	})

	t.Run("cancels on corrupt job data", func(t *testing.T) {
		h := activatekey.NewJobHandler(nil, testLocalTarget)
		res, err := h.ResolveTasks(t.Context(), orbital.Job{Type: activatekey.JobType, Data: []byte("not-json")}, "")
		require.NoError(t, err)
		assert.Equal(t, cancelType, res.Type())
	})
}
