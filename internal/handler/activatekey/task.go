package activatekey

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/internal/agentclient"
	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	agentkeys "github.com/openkcm/krypton/pkg/api/v1/proto/agents/keys"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// retryBackoff is how long the handler waits before orbital re-delivers a task
// that hit a transient error, guarding against hot-looping on infra issues.
const retryBackoff = 30 * time.Second

// TaskHandler activates a single key in-process on root's embedded operator.
//
// The handler is single-pass and idempotent: every step is a compare-and-set
// transition or an idempotent agent call, and the whole activation for a key is
// one atomic transaction (root-managed) or an idempotent agent call followed by
// one atomic root-side transaction (agent-managed). A re-delivered task that
// already finished short-circuits because the key is Active.
type TaskHandler struct {
	rootName        string
	transactor      store.Transactor
	keyStore        store.Key
	keyVersionStore store.KeyVersion
	manager         *keyprocessor.Manager
	agents          agentclient.Provider
}

// NewTaskHandler builds the per-key task handler. rootName is root's own name
// (a key's ManagedBy equal to it means root-managed); agents provides the mTLS
// clients used to activate agent-managed keys.
func NewTaskHandler(
	rootName string,
	transactor store.Transactor,
	keyStore store.Key,
	keyVersionStore store.KeyVersion,
	manager *keyprocessor.Manager,
	agents agentclient.Provider,
) *TaskHandler {
	return &TaskHandler{
		rootName:        rootName,
		transactor:      transactor,
		keyStore:        keyStore,
		keyVersionStore: keyVersionStore,
		manager:         manager,
		agents:          agents,
	}
}

func (h *TaskHandler) TaskType() string {
	return TaskType
}

func (h *TaskHandler) Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	var data TaskData
	if err := json.Unmarshal(req.TaskData, &data); err != nil {
		resp.Fail(fmt.Sprintf("unmarshal task data: %v", err))
		return
	}

	key, err := h.keyStore.GetKeyByID(ctx, data.KeyID, data.TenantID)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			resp.Fail("key not found: " + data.KeyID)
			return
		}
		slogctx.Warn(ctx, "transient error loading key, will retry", "err", err, "keyID", data.KeyID)
		resp.ContinueAndWaitFor(retryBackoff)
		return
	}

	// Idempotent short-circuit: nothing to do if the key is already active.
	if key.LifeCycleState == model.KeyLifeCycleActive {
		resp.Complete()
		return
	}

	if key.ManagedBy == h.rootName {
		h.activateRootManaged(ctx, key, resp)
		return
	}

	h.activateAgentManaged(ctx, key, resp)
}

// activateRootManaged seals the key material on root in one atomic transaction,
// the same chain admin ActivateKey used to run for every non-root key.
func (h *TaskHandler) activateRootManaged(ctx context.Context, key *model.Key, resp *orbital.HandlerResponse) {
	resolve := keyoperator.InitKeyVersion(key.TenantID, key.ID)

	err := store.ChainTransaction(ctx, h.transactor,
		keyoperator.UpdateKeyState(key.TenantID, key.ID, keyoperator.Transition{
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
			ToLifeCycle:    model.KeyLifeCycleActive,
			FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingCompleted},
			ToProcessing:   model.KeyProcessingInProgress,
		}),
		keyoperator.CreateKeyVersion(key.TenantID, key.ID, resolve),
		keyoperator.GenerateAndSealKeyMaterial(h.manager, key.TenantID, key.ID, resolve),
		keyoperator.UpdateKeyVersionState(key.TenantID, key.ID, resolve, keyoperator.VersionTransition{
			FromProcessing: []model.KeyVersionProcessingState{model.KeyVersionActivating},
			ToProcessing:   model.KeyVersionUsable,
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
			ToLifeCycle:    model.KeyLifeCycleActive,
		}),
		keyoperator.UpdateKeyState(key.TenantID, key.ID, keyoperator.Transition{
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCycleActive},
			ToLifeCycle:    model.KeyLifeCycleActive,
			FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingInProgress},
			ToProcessing:   model.KeyProcessingCompleted,
		}),
	)
	if err != nil {
		// Retry is the default: a rejected transition or seal failure is most
		// likely transient (e.g. a parent version not yet visible). The chain is
		// atomic, so a failed attempt leaves the key untouched for the next tick.
		slogctx.Warn(ctx, "root-managed activation failed, will retry", "err", err, "keyID", key.ID)
		resp.ContinueAndWaitFor(retryBackoff)
		return
	}

	slogctx.Info(ctx, "root-managed key activated", "keyID", key.ID, "tenant", key.TenantID)
	resp.Complete()
}

// activateAgentManaged activates a key that lives on an agent: it resolves the
// parent key version from root's store, calls the agent's ActivateKey gRPC, and
// records a metadata-only version row on root so descendant layers can resolve
// their parent key version.
func (h *TaskHandler) activateAgentManaged(ctx context.Context, key *model.Key, resp *orbital.HandlerResponse) {
	parentKeyVersion, err := h.resolveParentKeyVersion(ctx, key)
	if err != nil {
		// Parent's usable version is not visible on root yet — retry.
		slogctx.Warn(ctx, "parent key version not ready, will retry", "err", err, "keyID", key.ID)
		resp.ContinueAndWaitFor(retryBackoff)
		return
	}

	cli, err := h.agents.Client(key.ManagedBy)
	if err != nil {
		// No connection configured for the owning agent is a terminal misconfig.
		resp.Fail(fmt.Sprintf("resolve agent client for %q: %v", key.ManagedBy, err))
		return
	}

	req := &agentkeys.ActivateKeyRequest{
		TenantId: key.TenantID,
		KeyId:    key.ID,
	}
	if parentKeyVersion != nil {
		v := int32(*parentKeyVersion)
		req.ParentKeyVersion = &v
	}

	if _, err := cli.ActivateKey(ctx, req); err != nil {
		if proto.CodeFromError(err) == proto.Code_ERROR_CODE_ABORT {
			resp.Fail(fmt.Sprintf("agent %q rejected activation: %v", key.ManagedBy, err))
			return
		}
		slogctx.Warn(ctx, "agent activation failed, will retry", "err", err, "keyID", key.ID, "agent", key.ManagedBy)
		resp.ContinueAndWaitFor(retryBackoff)
		return
	}

	if err := h.finalizeAgentManaged(ctx, key, parentKeyVersion); err != nil {
		slogctx.Warn(ctx, "root-side finalize failed, will retry", "err", err, "keyID", key.ID)
		resp.ContinueAndWaitFor(retryBackoff)
		return
	}

	slogctx.Info(ctx, "agent-managed key activated", "keyID", key.ID, "tenant", key.TenantID, "agent", key.ManagedBy)
	resp.Complete()
}

// finalizeAgentManaged records root's metadata-only view of an agent-activated
// key: it flips the key to Active and writes a usable v1 version row WITHOUT
// sealing material (the material lives on the agent). Descendant layers resolve
// their parent key version from this row.
func (h *TaskHandler) finalizeAgentManaged(ctx context.Context, key *model.Key, parentKeyVersion *int) error {
	resolve := keyoperator.InitAgentKeyVersion(key.TenantID, key.ID, parentKeyVersion)

	return store.ChainTransaction(ctx, h.transactor,
		keyoperator.UpdateKeyState(key.TenantID, key.ID, keyoperator.Transition{
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
			ToLifeCycle:    model.KeyLifeCycleActive,
			FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingCompleted},
			ToProcessing:   model.KeyProcessingInProgress,
		}),
		keyoperator.CreateKeyVersion(key.TenantID, key.ID, resolve),
		keyoperator.UpdateKeyVersionState(key.TenantID, key.ID, resolve, keyoperator.VersionTransition{
			FromProcessing: []model.KeyVersionProcessingState{model.KeyVersionActivating},
			ToProcessing:   model.KeyVersionUsable,
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
			ToLifeCycle:    model.KeyLifeCycleActive,
		}),
		keyoperator.UpdateKeyState(key.TenantID, key.ID, keyoperator.Transition{
			FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCycleActive},
			ToLifeCycle:    model.KeyLifeCycleActive,
			FromProcessing: []model.KeyProcessingStatus{model.KeyProcessingInProgress},
			ToProcessing:   model.KeyProcessingCompleted,
		}),
	)
}

// resolveParentKeyVersion returns the parent's latest usable/active version from
// root's store, or nil when the key has no parent. It errors when the key has a
// parent but no usable version is visible yet (the parent layer hasn't landed on
// root), which the caller treats as retryable.
func (h *TaskHandler) resolveParentKeyVersion(ctx context.Context, key *model.Key) (*int, error) {
	if key.ParentID == nil {
		// A root key has no parent version; nil is the intended sentinel here.
		return nil, nil //nolint:nilnil
	}

	res, err := h.keyVersionStore.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
		TenantID:        key.TenantID,
		KeyID:           *key.ParentID,
		ProcessingState: model.KeyVersionUsable,
		LifeCycleState:  model.KeyLifeCycleActive,
		OrderBy: []store.KeyVersionOrder{
			store.KeyVersionOrderVersionDesc,
			store.KeyVersionOrderRevisionDesc,
		},
		Limit: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("list parent key versions: %w", err)
	}
	if len(res.KeyVersions) == 0 {
		return nil, fmt.Errorf("%w: parent %s", keyoperator.ErrParentNoUsableVersion, *key.ParentID)
	}

	v := res.KeyVersions[0].Version
	return &v, nil
}
