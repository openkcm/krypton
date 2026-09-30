package announcekey_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/agentclient"
	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	agentkeys "github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
)

// fakeKeyClient is a stub agentkeys.KeyServiceClient that records the last
// UpsertKey request and returns a canned response/error.
type fakeKeyClient struct {
	upsertResp *agentkeys.UpsertKeyResponse
	upsertErr  error
	gotUpsert  *agentkeys.UpsertKeyRequest
}

func (c *fakeKeyClient) UpsertKey(_ context.Context, in *agentkeys.UpsertKeyRequest, _ ...grpc.CallOption) (*agentkeys.UpsertKeyResponse, error) {
	c.gotUpsert = in
	if c.upsertErr != nil {
		return nil, c.upsertErr
	}
	if c.upsertResp != nil {
		return c.upsertResp, nil
	}
	return &agentkeys.UpsertKeyResponse{}, nil
}

func (c *fakeKeyClient) ActivateKey(_ context.Context, _ *agentkeys.ActivateKeyRequest, _ ...grpc.CallOption) (*agentkeys.ActivateKeyResponse, error) {
	return &agentkeys.ActivateKeyResponse{}, nil
}

// fakeProvider is an agentclient.Provider returning a fixed client, or an error
// when clientErr is set (simulating an unknown agent).
type fakeProvider struct {
	client    agentkeys.KeyServiceClient
	clientErr error
	gotName   string
}

func (p *fakeProvider) Client(agentName string) (agentkeys.KeyServiceClient, error) {
	p.gotName = agentName
	if p.clientErr != nil {
		return nil, p.clientErr
	}
	return p.client, nil
}

var _ agentclient.Provider = (*fakeProvider)(nil)

func executeTask(t *testing.T, h orbital.HandlerFunc, data []byte) orbital.TaskResponse {
	t.Helper()
	return orbital.ExecuteHandler(t.Context(), h, orbital.TaskRequest{
		TaskID: uuid.NewV7(),
		Type:   announcekey.TaskType,
		Data:   data,
	})
}

func announceTaskData(t *testing.T, target string) []byte {
	t.Helper()
	payload, err := json.Marshal(announcekey.TaskData{
		KeyID:    uuid.New().String(),
		TenantID: uuid.New().String(),
		Kind:     "K0",
		Name:     "freshly-announced",
		Target:   target,
	})
	require.NoError(t, err)
	return payload
}

func TestTaskHandler_HappyPath(t *testing.T) {
	client := &fakeKeyClient{}
	provider := &fakeProvider{client: client}
	handler := announcekey.NewTaskHandler(provider)

	resp := executeTask(t, handler.Handle, announceTaskData(t, "agent-1"))
	assert.Equal(t, string(orbital.TaskStatusDone), resp.Status, "expected DONE, got %q (%s)", resp.Status, resp.ErrorMessage)
	assert.Empty(t, resp.ErrorMessage)

	require.NotNil(t, client.gotUpsert)
	assert.Equal(t, "agent-1", provider.gotName)
	assert.Equal(t, "agent-1", client.gotUpsert.GetManagedBy())
	assert.Equal(t, "freshly-announced", client.gotUpsert.GetName())
	assert.Equal(t, "K0", client.gotUpsert.GetKind())
}

func TestTaskHandler_CorruptPayload_TerminalFail(t *testing.T) {
	handler := announcekey.NewTaskHandler(&fakeProvider{client: &fakeKeyClient{}})

	resp := executeTask(t, handler.Handle, []byte("not-json"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "unmarshal task data")
}

func TestTaskHandler_UnknownAgent_TerminalFail(t *testing.T) {
	handler := announcekey.NewTaskHandler(&fakeProvider{clientErr: agentclient.ErrUnknownAgent})

	resp := executeTask(t, handler.Handle, announceTaskData(t, "ghost"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "resolve agent client")
}

func TestTaskHandler_AbortError_TerminalFail(t *testing.T) {
	abortErr := proto.ErrDetailsWithCode(
		status.New(codes.InvalidArgument, "bad key"),
		proto.Code_ERROR_CODE_ABORT,
	)
	client := &fakeKeyClient{upsertErr: abortErr}
	handler := announcekey.NewTaskHandler(&fakeProvider{client: client})

	resp := executeTask(t, handler.Handle, announceTaskData(t, "agent-1"))
	assert.Equal(t, string(orbital.TaskStatusFailed), resp.Status)
	assert.Contains(t, resp.ErrorMessage, "rejected upsert")
}

func TestTaskHandler_TransientError_RetriesWithBackoff(t *testing.T) {
	client := &fakeKeyClient{upsertErr: errors.New("network blip")}
	handler := announcekey.NewTaskHandler(&fakeProvider{client: client})

	resp := executeTask(t, handler.Handle, announceTaskData(t, "agent-1"))
	assert.Equal(t, string(orbital.TaskStatusProcessing), resp.Status, "transient errors must not be terminal")
	assert.Positive(t, resp.ReconcileAfterSec, "expected non-zero backoff before retry")
}
