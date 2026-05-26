package handler

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openkcm/orbital"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/internal/reconciler/handler/announcekey"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

func NewAnnounceKey(keyStore store.Key) orbital.HandlerFunc {
	return func(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
		var data announcekey.TaskData
		if err := json.Unmarshal(req.TaskData, &data); err != nil {
			resp.Fail(fmt.Sprintf("unmarshal task data: %v", err))
			return
		}

		var parentID *string
		if data.ParentID != "" {
			parentID = &data.ParentID
		}

		key := model.NewKey(data.TenantID, data.Name, data.Kind, parentID, data.Target, data.Labels)
		key.ID = data.KeyID
		key.State = model.KeyStatePreActivation

		if err := keyStore.CreateKey(ctx, key); err != nil {
			resp.Fail(fmt.Sprintf("store key: %v", err))
			return
		}

		slogctx.Info(ctx, "key announced", "keyID", key.ID, "tenant", key.TenantID)
		resp.Complete()
	}
}
