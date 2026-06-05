package announcekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// retryBackoff is how long the agent waits before orbital re-delivers a task
// that hit a transient error. Hot-looping on transient infra issues is the
// failure mode this guards against.
const retryBackoff = 30 * time.Second

// Postgres SQLSTATE codes used to classify CreateKey errors.
const (
	pgCodeUniqueViolation     = "23505"
	pgCodeForeignKeyViolation = "23503"
)

// NewTaskHandler returns the agent-side orbital handler for an announce-key
// task. It persists the announced key in the agent's local key store.
//
// Error classification follows the principle that retry should be the
// default — only known-terminal failures call resp.Fail(). Per orbital's
// HandlerResponse semantics, omitting Fail/Complete keeps the task in
// processing state and orbital re-delivers it.
func NewTaskHandler(keyStore store.Key) orbital.HandlerFunc {
	return func(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
		var data TaskData
		if err := json.Unmarshal(req.TaskData, &data); err != nil {
			// Terminal: payload is corrupt, retrying won't help.
			resp.Fail(fmt.Sprintf("unmarshal task data: %v", err))
			return
		}

		var parentID *string
		if data.ParentID != "" {
			parentID = &data.ParentID
		}

		key := model.NewKey(data.TenantID, data.Name, data.Kind, parentID, data.Target, data.Labels)
		key.ID = data.KeyID
		key.LifeCycleState = model.KeyLifeCyclePreActivation

		err := keyStore.CreateKey(ctx, key)
		if err == nil {
			slogctx.Info(ctx, "key announced", "keyID", key.ID, "tenant", key.TenantID)
			resp.Complete()
			return
		}

		// Idempotent re-delivery: agent already has the key.
		if errors.Is(err, store.ErrKeyAlreadyExists) {
			slogctx.Info(ctx, "key already announced (idempotent)", "keyID", key.ID)
			resp.Complete()
			return
		}

		// Classify the underlying postgres error for terminal vs retryable.
		if pqErr, ok := errors.AsType[*pq.Error](err); ok {
			switch string(pqErr.Code) {
			case pgCodeForeignKeyViolation:
				// Tenant missing on agent (or other FK violation) — retrying
				// won't help until upstream fixes the data.
				resp.Fail(fmt.Sprintf("foreign key violation while storing key: %v", err))
				return
			case pgCodeUniqueViolation:
				// Belt-and-suspenders: should already be caught above as
				// ErrKeyAlreadyExists, but be defensive.
				resp.Complete()
				return
			}
		}

		// Unknown error → leave in processing state with a backoff so orbital
		// re-delivers without hot-looping.
		slogctx.Warn(ctx, "transient error storing key, will retry", "err", err, "keyID", key.ID)
		resp.ContinueAndWaitFor(retryBackoff)
	}
}
