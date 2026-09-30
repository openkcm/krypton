package announcekey

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/internal/agentclient"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	agentkeys "github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/model"
)

// retryBackoff is how long root waits before orbital re-delivers a task that
// hit a transient error. Hot-looping on transient infra issues is the failure
// mode this guards against.
const retryBackoff = 30 * time.Second

// TaskHandler runs on root's embedded operator. It announces a key to its
// owning agent by calling the agent's UpsertKey gRPC (an idempotent upsert),
// replacing the legacy agent-local persistence over an insecure rpc push.
//
// Error classification follows the principle that retry is the default: only a
// terminal gRPC error (ABORT — bad request the agent will keep rejecting) calls
// resp.Fail(); anything else backs off and is re-delivered.
type TaskHandler struct {
	agents agentclient.Provider
}

// NewTaskHandler returns the embedded announce-key task handler. agents
// provides the mTLS client to the owning agent.
func NewTaskHandler(agents agentclient.Provider) *TaskHandler {
	return &TaskHandler{agents: agents}
}

func (h *TaskHandler) TaskType() string {
	return TaskType
}

func (h *TaskHandler) Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	var data TaskData
	if err := json.Unmarshal(req.TaskData, &data); err != nil {
		// Terminal: payload is corrupt, retrying won't help.
		resp.Fail(fmt.Sprintf("unmarshal task data: %v", err))
		return
	}

	cli, err := h.agents.Client(data.Target)
	if err != nil {
		// No connection configured for the owning agent is a terminal misconfig.
		resp.Fail(fmt.Sprintf("resolve agent client for %q: %v", data.Target, err))
		return
	}

	_, err = cli.UpsertKey(ctx, &agentkeys.UpsertKeyRequest{
		TenantId:       data.TenantID,
		KeyId:          data.KeyID,
		Kind:           data.Kind,
		Name:           data.Name,
		ParentId:       data.ParentID,
		ManagedBy:      data.Target,
		LifecycleState: string(model.KeyLifeCyclePreActivation),
		Labels:         data.Labels,
	})
	if err != nil {
		if proto.CodeFromError(err) == proto.Code_ERROR_CODE_ABORT {
			resp.Fail(fmt.Sprintf("agent %q rejected upsert: %v", data.Target, err))
			return
		}
		slogctx.Warn(ctx, "transient error announcing key, will retry", "err", err, "keyID", data.KeyID, "agent", data.Target)
		resp.ContinueAndWaitFor(retryBackoff)
		return
	}

	slogctx.Info(ctx, "key announced", "keyID", data.KeyID, "tenant", data.TenantID, "agent", data.Target)
	resp.Complete()
}
