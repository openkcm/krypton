package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
)

type actionView struct {
	Type      string
	Status    string
	KeyID     string
	ActionID  string
	CreatedAt clock.UnixNano
	UpdatedAt clock.UnixNano
}

func buildActionView(a *keys.Action) actionView {
	return actionView{
		ActionID:  a.GetId(),
		KeyID:     a.GetKeyId(),
		Type:      a.GetType(),
		Status:    a.GetStatus(),
		CreatedAt: clock.UnixNano(a.GetCreatedAt()),
		UpdatedAt: clock.UnixNano(a.GetUpdatedAt()),
	}
}

func buildKeyRows(a *keys.Action) []keyRow {
	var rows []keyRow
	for _, layer := range a.GetKeyTree() {
		for _, k := range layer.GetKeys() {
			rows = append(rows, newKeyRow(k))
		}
	}
	return rows
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
		actionID string
		tenantID string
		asJSON   bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the status of an action",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				tID, err := selectedTenantID()
				if err != nil {
					return fmt.Errorf("failed to get selected tenant: %w", err)
				}
				tenantID = tID
			}

			action, err := getAction(cmd.Context(), serverAddr, tenantID, actionID)
			if err != nil {
				return err
			}
			return renderActionStatus(action, cmd.OutOrStdout(), asJSON)
		},
	}

	cmd.Flags().StringVar(&actionID, "action-id", "", "id of the action")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "id of the tenant")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")
	_ = cmd.MarkFlagRequired("action-id")

	return cmd
}

func getAction(ctx context.Context, serverAddr, tenantID, id string) (*keys.Action, error) {
	conn, err := newConnection(ctx, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	client := keys.NewKeyServiceClient(conn)
	resp, err := client.GetAction(ctx, &keys.GetActionRequest{
		Id:       id,
		TenantId: tenantID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get action: %w", err)
	}
	action := resp.GetAction()
	if action == nil {
		return nil, errors.New("server returned an empty action")
	}
	return action, nil
}

func renderActionStatus(a *keys.Action, w io.Writer, asJSON bool) error {
	action := buildActionView(a)
	keys := buildKeyRows(a)

	if asJSON {
		combined := struct {
			Action actionView
			Keys   []keyRow
		}{action, keys}
		b, err := output.From(combined)
		if err != nil {
			return err
		}
		return formatOutput(b, true).To(w)
	}

	ab, err := output.From(action)
	if err != nil {
		return err
	}

	err = ab.Format(timeFormatter).As(output.KeyValue).To(w)
	if err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w); err != nil {
		return err
	}

	kb, err := output.From(keys)
	if err != nil {
		return err
	}
	return formatOutput(kb, false).To(w)
}
