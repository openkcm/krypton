package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/actions"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
)

var actionTypeLabels = map[actions.ActionType]string{
	actions.ActionType_ANNOUNCE_KEY: "announce-key",
	actions.ActionType_ACTIVATE_KEY: "activate-key",
}

func actionTypeLabel(t actions.ActionType) string {
	if s, ok := actionTypeLabels[t]; ok {
		return s
	}
	return t.String()
}

type actionView struct {
	Type      string
	Cascading bool
	Status    string
	TargetID  string
	ActionID  string
	CreatedAt clock.UnixNano
	UpdatedAt clock.UnixNano
}

func buildActionView(a *actions.Action) actionView {
	return actionView{
		ActionID:  a.GetId(),
		TargetID:  a.GetTargetId(),
		Type:      actionTypeLabel(a.GetType()),
		Cascading: a.GetCascading(),
		Status:    a.GetStatus(),
		CreatedAt: clock.UnixNano(a.GetCreatedAt()),
		UpdatedAt: clock.UnixNano(a.GetUpdatedAt()),
	}
}

func actionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "action",
		Short: "Inspect actions",
	}
	cmd.AddCommand(actionStatusCmd())
	return cmd
}

func actionStatusCmd() *cobra.Command {
	var (
		actionID   string
		targetInfo bool
		asJSON     bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the status of an action",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			w := cmd.OutOrStdout()

			conn, err := newConnection(ctx, serverAddr)
			if err != nil {
				return fmt.Errorf("failed to connect: %w", err)
			}
			defer conn.Close()

			action, err := getAction(ctx, conn, actionID)
			if err != nil {
				return err
			}
			view := buildActionView(action)

			if !targetInfo {
				return renderOverview(view, w, asJSON)
			}

			info, err := getTargetInfo(ctx, conn, action)
			if err != nil {
				return err
			}
			return renderOverviewWithInfo(view, info, w, asJSON)
		},
	}

	cmd.Flags().StringVar(&actionID, "action-id", "", "id of the action")
	cmd.Flags().BoolVar(&targetInfo, "target-info", false, "also fetch and render target-specific info (issues a second call)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")
	_ = cmd.MarkFlagRequired("action-id")

	return cmd
}

func getAction(ctx context.Context, conn *grpc.ClientConn, id string) (*actions.Action, error) {
	resp, err := actions.NewActionServiceClient(conn).
		GetAction(ctx, &actions.GetActionRequest{Id: id})
	if err != nil {
		return nil, fmt.Errorf("failed to get action: %w", err)
	}
	if resp.GetAction() == nil {
		return nil, errors.New("server returned an empty action")
	}
	return resp.GetAction(), nil
}

func getTargetInfo(ctx context.Context, conn *grpc.ClientConn, a *actions.Action) (any, error) {
	switch a.GetTargetType() {
	case actions.TargetType_TARGET_TYPE_KEY:
		id, err := parseTargetID(a.GetTargetId(), "tenant", "key")
		if err != nil {
			return nil, err
		}
		client := keys.NewKeyServiceClient(conn)
		if a.GetCascading() {
			return getKeyTree(ctx, client, id["tenant"], id["key"])
		}
		return getKey(ctx, client, id["tenant"], id["key"])
	default:
		return nil, fmt.Errorf("target-info not supported for target_type %q", a.GetTargetType())
	}
}

// parseTargetID splits target_id on ':' and asserts one non-empty part per
// name. Returns a map keyed by the given names in order.
func parseTargetID(id string, names ...string) (map[string]string, error) {
	parts := strings.Split(id, ":")
	if len(parts) != len(names) {
		return nil, fmt.Errorf(
			"invalid target_id %q: expected %d parts (%s), got %d",
			id, len(names), strings.Join(names, ":"), len(parts),
		)
	}
	out := make(map[string]string, len(names))
	for i, name := range names {
		if parts[i] == "" {
			return nil, fmt.Errorf("invalid target_id %q: empty %s", id, name)
		}
		out[name] = parts[i]
	}
	return out, nil
}

func getKey(ctx context.Context, client keys.KeyServiceClient, tenantID, keyID string) (keyRow, error) {
	resp, err := client.GetKey(ctx, &keys.GetKeyRequest{Id: keyID, TenantId: tenantID})
	if err != nil {
		return keyRow{}, fmt.Errorf("failed to get key: %w", err)
	}
	if resp.GetKey() == nil {
		return keyRow{}, errors.New("server returned an empty key")
	}
	return newKeyRow(resp.GetKey()), nil
}

func getKeyTree(ctx context.Context, client keys.KeyServiceClient, tenantID, keyID string) ([]keyRow, error) {
	resp, err := client.GetDescendantKeys(ctx, &keys.GetDescendantKeysRequest{Id: keyID, TenantId: tenantID})
	if err != nil {
		return nil, fmt.Errorf("failed to get descendant keys: %w", err)
	}

	rows := make([]keyRow, 0)
	for _, tree := range resp.GetKeyTree() {
		for _, k := range tree.GetKeys() {
			rows = append(rows, newKeyRow(k))
		}
	}
	return rows, nil
}

func renderOverview(view actionView, w io.Writer, asJSON bool) error {
	ab, err := output.From(view)
	if err != nil {
		return err
	}
	if asJSON {
		return formatOutput(ab, true).To(w)
	}
	return ab.Format(timeFormatter).As(output.KeyValue).To(w)
}

func renderOverviewWithInfo(view actionView, info any, w io.Writer, asJSON bool) error {
	if asJSON {
		combined := struct {
			Action     actionView
			TargetInfo any
		}{view, info}
		b, err := output.From(combined)
		if err != nil {
			return err
		}
		return formatOutput(b, true).To(w)
	}

	if err := renderOverview(view, w, false); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	tb, err := output.From(info)
	if err != nil {
		return err
	}
	return formatOutput(tb, false).To(w)
}
