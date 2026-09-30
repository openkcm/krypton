package activatekey_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/agentclient"
	"github.com/openkcm/krypton/internal/handler/activatekey"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// fakeKeyStore embeds store.Key so unimplemented methods panic if reached, and
// overrides GetKeyByID to return canned values for the classification tests.
type fakeKeyStore struct {
	store.Key

	key *model.Key
	err error
}

func (f *fakeKeyStore) GetKeyByID(_ context.Context, _, _ string) (*model.Key, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.key, nil
}

func taskData(t *testing.T, tenantID, keyID string) []byte {
	t.Helper()
	data, err := json.Marshal(activatekey.TaskData{TenantID: tenantID, KeyID: keyID})
	require.NoError(t, err)
	return data
}

func executeTask(t *testing.T, h *activatekey.TaskHandler, data []byte) orbital.TaskResponse {
	t.Helper()
	return orbital.ExecuteHandler(t.Context(), h.Handle, orbital.TaskRequest{
		TaskID: uuid.NewV7(),
		Type:   activatekey.TaskType,
		Data:   data,
	})
}

// newClassifierHandler builds a task handler with only the collaborators the
// pre-DB classification branches touch (key load + agent call).
func newClassifierHandler(keyStore store.Key, agents agentclient.Provider) *activatekey.TaskHandler {
	return activatekey.NewTaskHandler(testRootName, nil, keyStore, nil, nil, agents)
}

func TestTaskHandler_TaskType(t *testing.T) {
	h := newClassifierHandler(&fakeKeyStore{}, &fakeProvider{})
	assert.Equal(t, activatekey.TaskType, h.TaskType())
}

func TestTaskHandler_CorruptPayload_TerminalFail(t *testing.T) {
	h := newClassifierHandler(&fakeKeyStore{}, &fakeProvider{})
	resp := executeTask(t, h, []byte("not-json"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "unmarshal task data")
}

func TestTaskHandler_KeyNotFound_TerminalFail(t *testing.T) {
	h := newClassifierHandler(&fakeKeyStore{err: store.ErrKeyNotFound}, &fakeProvider{})
	resp := executeTask(t, h, taskData(t, "tenant", "missing"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
}

func TestTaskHandler_TransientLoadError_Retries(t *testing.T) {
	h := newClassifierHandler(&fakeKeyStore{err: errors.New("db blip")}, &fakeProvider{})
	resp := executeTask(t, h, taskData(t, "tenant", "key"))
	assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
	assert.Positive(t, resp.ReconcileAfterSec)
}

func TestTaskHandler_AlreadyActive_ShortCircuits(t *testing.T) {
	active := &model.Key{ID: "k", TenantID: "t", ManagedBy: testRootName, LifeCycleState: model.KeyLifeCycleActive}
	h := newClassifierHandler(&fakeKeyStore{key: active}, &fakeProvider{})
	resp := executeTask(t, h, taskData(t, "t", "k"))
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status, "an active key needs no work")
}

func TestTaskHandler_AgentManaged_UnknownAgent_TerminalFail(t *testing.T) {
	key := &model.Key{ID: "k", TenantID: "t", ManagedBy: "ghost", LifeCycleState: model.KeyLifeCyclePreActivation}
	h := newClassifierHandler(&fakeKeyStore{key: key}, &fakeProvider{clientErr: agentclient.ErrUnknownAgent})
	resp := executeTask(t, h, taskData(t, "t", "k"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "resolve agent client")
}

func TestTaskHandler_AgentManaged_AbortError_TerminalFail(t *testing.T) {
	abortErr := proto.ErrDetailsWithCode(
		status.New(codes.InvalidArgument, "bad key"),
		proto.Code_ERROR_CODE_ABORT,
	)
	key := &model.Key{ID: "k", TenantID: "t", ManagedBy: "agent-1", LifeCycleState: model.KeyLifeCyclePreActivation}
	client := &fakeKeyClient{activateErr: abortErr}
	h := newClassifierHandler(&fakeKeyStore{key: key}, &fakeProvider{client: client})

	resp := executeTask(t, h, taskData(t, "t", "k"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "rejected activation")
}

func TestTaskHandler_AgentManaged_TransientError_Retries(t *testing.T) {
	key := &model.Key{ID: "k", TenantID: "t", ManagedBy: "agent-1", LifeCycleState: model.KeyLifeCyclePreActivation}
	client := &fakeKeyClient{activateErr: errors.New("network blip")}
	h := newClassifierHandler(&fakeKeyStore{key: key}, &fakeProvider{client: client})

	resp := executeTask(t, h, taskData(t, "t", "k"))
	assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status)
	assert.Positive(t, resp.ReconcileAfterSec)
}

// --- DB-backed happy paths ---

func TestTaskHandler_RootManaged_HappyPath(t *testing.T) {
	db := newRootDB(t)
	s := newStores(t, db)
	tenant := seedTenant(t, s.tenantStore)

	h := activatekey.NewTaskHandler(testRootName, s.transactor, s.keyStore, s.keyVersionStore, s.manager, &fakeProvider{})

	// Activate the root first so the child has a parent version to seal against.
	k0 := seedKey(t, s.keyStore, tenant.ID, "k0", "K0", testRootName, nil)
	resp := executeTask(t, h, taskData(t, tenant.ID, k0.ID))
	require.Equal(t, string(orbital.TaskStatusDone), resp.Status, "root activate: %s", resp.ErrorMessage)
	assertKeyActiveWithUsableVersion(t, s, tenant.ID, k0.ID)

	// Then the child, root-managed and sealed in-process.
	k1 := seedKey(t, s.keyStore, tenant.ID, "k1", "K1", testRootName, &k0.ID)
	resp = executeTask(t, h, taskData(t, tenant.ID, k1.ID))
	require.Equal(t, string(orbital.TaskStatusDone), resp.Status, "child activate: %s", resp.ErrorMessage)
	assertKeyActiveWithUsableVersion(t, s, tenant.ID, k1.ID)
}

func TestTaskHandler_RootManaged_IdempotentRerun(t *testing.T) {
	db := newRootDB(t)
	s := newStores(t, db)
	tenant := seedTenant(t, s.tenantStore)

	h := activatekey.NewTaskHandler(testRootName, s.transactor, s.keyStore, s.keyVersionStore, s.manager, &fakeProvider{})
	k0 := seedKey(t, s.keyStore, tenant.ID, "k0", "K0", testRootName, nil)

	first := executeTask(t, h, taskData(t, tenant.ID, k0.ID))
	require.Equal(t, string(orbital.TaskStatusDone), first.Status, first.ErrorMessage)

	second := executeTask(t, h, taskData(t, tenant.ID, k0.ID))
	require.Equal(t, string(orbital.TaskStatusDone), second.Status, "re-running an active key must be a no-op DONE")

	// Still exactly one usable version — the rerun did not seal a second time.
	res, err := s.keyVersionStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
		TenantID:        tenant.ID,
		KeyID:           k0.ID,
		ProcessingState: model.KeyVersionUsable,
		LifeCycleState:  model.KeyLifeCycleActive,
	})
	require.NoError(t, err)
	assert.Len(t, res.KeyVersions, 1)
}

func TestTaskHandler_AgentManaged_HappyPath(t *testing.T) {
	db := newRootDB(t)
	s := newStores(t, db)
	tenant := seedTenant(t, s.tenantStore)

	// Root parent must be active so the agent-managed child can resolve its
	// parent key version from root's store.
	rootHandler := activatekey.NewTaskHandler(testRootName, s.transactor, s.keyStore, s.keyVersionStore, s.manager, &fakeProvider{})
	k0 := seedKey(t, s.keyStore, tenant.ID, "k0", "K0", testRootName, nil)
	require.Equal(t, string(orbital.TaskStatusDone), executeTask(t, rootHandler, taskData(t, tenant.ID, k0.ID)).Status)

	client := &fakeKeyClient{}
	provider := &fakeProvider{client: client}
	h := activatekey.NewTaskHandler(testRootName, s.transactor, s.keyStore, s.keyVersionStore, s.manager, provider)

	k1 := seedKey(t, s.keyStore, tenant.ID, "k1", "K1", "agent-1", &k0.ID)
	resp := executeTask(t, h, taskData(t, tenant.ID, k1.ID))
	require.Equal(t, string(orbital.TaskStatusDone), resp.Status, "agent activate: %s", resp.ErrorMessage)

	// The agent was called with the resolved parent key version.
	assert.Equal(t, "agent-1", provider.gotName)
	require.NotNil(t, client.gotActivate)
	assert.Equal(t, k1.ID, client.gotActivate.GetKeyId())
	require.NotNil(t, client.gotActivate.ParentKeyVersion, "parent version must be resolved and forwarded")

	// Root records a metadata-only usable version so descendants can chain.
	assertKeyActiveWithUsableVersion(t, s, tenant.ID, k1.ID)
}

func assertKeyActiveWithUsableVersion(t *testing.T, s testStores, tenantID, keyID string) {
	t.Helper()
	key, err := s.keyStore.GetKeyByID(t.Context(), keyID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, model.KeyLifeCycleActive, key.LifeCycleState)

	res, err := s.keyVersionStore.ListKeyVersions(t.Context(), store.ListKeyVersionsQuery{
		TenantID:        tenantID,
		KeyID:           keyID,
		ProcessingState: model.KeyVersionUsable,
		LifeCycleState:  model.KeyLifeCycleActive,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, res.KeyVersions, "expected a usable, active key version")
}
