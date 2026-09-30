package announcekey_test

import (
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

const rootName = "root"

func TestTaskHandler_HappyPath_NonRootTarget(t *testing.T) {
	rootDB := newRootDB(t)
	agent := startAgentServer(t)

	key := seedRootTenantAndKey(t, rootDB, "agent")
	seedAgentTenant(t, agent.db, key.TenantID)

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		newRegistry(t, "agent", agent),
		rootName,
	)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status, "got %q: %s", resp.Status, resp.ErrorMessage)

	got, err := storesql.NewKeyStore(rootDB).GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
	assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState)

	agentKey, err := agent.keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyLifeCyclePreActivation, agentKey.LifeCycleState)
}

func TestTaskHandler_HappyPath_RootTarget(t *testing.T) {
	rootDB := newRootDB(t)
	key := seedRootTenantAndKey(t, rootDB, rootName)

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		emptyRegistry(t),
		rootName,
	)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status, "got %q: %s", resp.Status, resp.ErrorMessage)

	got, err := storesql.NewKeyStore(rootDB).GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
}

func TestTaskHandler_RegistryMiss_TerminalFail(t *testing.T) {
	rootDB := newRootDB(t)
	agent := startAgentServer(t)

	key := seedRootTenantAndKey(t, rootDB, "unknown-agent")

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		newRegistry(t, "some-other-agent", agent),
		rootName,
	)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, `no connection registered for target "unknown-agent"`)

	got, err := storesql.NewKeyStore(rootDB).GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyProcessingFailed, got.KeyProcessingState.Status)
}

func TestTaskHandler_TenantAutoUpsertedOnAgent_Success(t *testing.T) {
	rootDB := newRootDB(t)
	agent := startAgentServer(t)

	key := seedRootTenantAndKey(t, rootDB, "agent")
	// tenant is not pre-seeded on the agent; validateAndUpsertTenant will create it

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		newRegistry(t, "agent", agent),
		rootName,
	)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status)

	got, err := storesql.NewKeyStore(rootDB).GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
}

func TestTaskHandler_RPCTransient_AgentDown_Retries(t *testing.T) {
	rootDB := newRootDB(t)
	agent := startAgentServer(t)

	key := seedRootTenantAndKey(t, rootDB, "agent")

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		newRegistry(t, "agent", agent),
		rootName,
	)

	// stop the server so the client sees codes.Unavailable
	agent.stop()

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
	assert.Positive(t, resp.ReconcileAfterSec)

	got, err := storesql.NewKeyStore(rootDB).GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyProcessingInProgress, got.KeyProcessingState.Status, "state must not advance on transient failure")
}

func TestTaskHandler_ValidateTransition_KeyNotFound_TerminalFail(t *testing.T) {
	rootDB := newRootDB(t)

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		emptyRegistry(t),
		rootName,
	)

	ghost := model.NewKey(createTenant(t, rootDB).Tenant.ID, "ghost", "K0", nil, rootName, nil)
	ghost.ID = uuid.New().String()

	resp := runTask(t, handler, taskPayload(t, ghost))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "not found")
}

func TestTaskHandler_TenantNotFound_TerminalFail(t *testing.T) {
	rootDB := newRootDB(t)

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		emptyRegistry(t),
		rootName,
	)

	key := model.NewKey(uuid.New().String(), "k0", "K0", nil, rootName, nil)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "not found")
}

func TestTaskHandler_TenantFetching_Error_Continue(t *testing.T) {
	rootDB := newRootDB(t)
	agent := startAgentServer(t)

	key := seedRootTenantAndKey(t, rootDB, "agent")

	dropTenantTable(t, rootDB) // simulate transient error on root

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		newRegistry(t, "agent", agent),
		rootName,
	)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status, "got %q: %s", resp.Status, resp.ErrorMessage)
	assert.Positive(t, resp.ReconcileAfterSec)

	_, err := agent.keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
	assert.ErrorIs(t, err, store.ErrKeyNotFound)
}

func TestTaskHandler_TenantUpsert_ReturnTerminalUpsert_Fail(t *testing.T) {
	rootDB := newRootDB(t)
	agent := startAgentServer(t)

	key := seedRootTenantAndKey(t, rootDB, "agent")

	// making tenant name as empty string will cause the agent to return a terminal error on UpsertTenant
	_, err := storesql.NewTenantStore(rootDB).UpsertTenant(t.Context(), store.UpsertTenantQuery{
		Tenant: model.Tenant{
			ID:   key.TenantID,
			Name: "",
		},
	})
	require.NoError(t, err)

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		newRegistry(t, "agent", agent),
		rootName,
	)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status, "got %q: %s", resp.Status, resp.ErrorMessage)

	got, err := storesql.NewKeyStore(rootDB).GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyProcessingFailed, got.KeyProcessingState.Status)
	assert.NotEqual(t, key.KeyProcessingState.Status, got.KeyProcessingState.Status)

	_, err = agent.keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
	assert.ErrorIs(t, err, store.ErrKeyNotFound)
}

func TestTaskHandler_TenantUpsert_In_Agent(t *testing.T) {
	rootDB := newRootDB(t)
	agent := startAgentServer(t)

	key := seedRootTenantAndKey(t, rootDB, "agent")

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		newRegistry(t, "agent", agent),
		rootName,
	)

	// before the task runs, the tenant should not exist on the agent
	_, err := agent.tenantStore.GetTenant(t.Context(), store.GetTenantQuery{ID: key.TenantID})
	assert.ErrorIs(t, err, store.ErrTenantNotFound)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status, "got %q: %s", resp.Status, resp.ErrorMessage)

	got, err := storesql.NewKeyStore(rootDB).GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyProcessingCompleted, got.KeyProcessingState.Status)
	assert.Equal(t, model.KeyLifeCyclePreActivation, got.LifeCycleState)

	agentKey, err := agent.keyStore.GetKeyByID(t.Context(), key.ID, key.TenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyLifeCyclePreActivation, agentKey.LifeCycleState)

	// after the task runs, the tenant should exist on the agent
	tenant, err := agent.tenantStore.GetTenant(t.Context(), store.GetTenantQuery{ID: key.TenantID})
	require.NoError(t, err)
	assert.Equal(t, key.TenantID, tenant.Tenant.ID)
}

func TestTaskHandler_ValidateTransition_InvalidTransition_TerminalFail(t *testing.T) {
	rootDB := newRootDB(t)
	keyStore := storesql.NewKeyStore(rootDB)

	key := seedRootTenantAndKey(t, rootDB, rootName)
	require.NoError(t, keyStore.UpdateKeyLifeCycleState(t.Context(), store.UpdateKeyLifeCycleStateQuery{
		ID:       key.ID,
		TenantID: key.TenantID,
		NewState: model.KeyLifeCycleActive,
	}))

	handler := announcekey.NewTaskHandler(
		storesql.NewTransactor(rootDB),
		emptyRegistry(t),
		rootName,
	)

	resp := runTask(t, handler, taskPayload(t, key))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "invalid key state transition")
}

func TestTaskHandler_CorruptPayload_TerminalFail(t *testing.T) {
	handler := announcekey.NewTaskHandler(nil, nil, rootName)

	resp := runTask(t, handler, []byte("not-json"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "unmarshal task data")
}

func TestTaskHandler_TaskType(t *testing.T) {
	handler := announcekey.NewTaskHandler(nil, nil, rootName)
	assert.Equal(t, announcekey.TaskType, handler.TaskType())
}
