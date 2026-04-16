package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/cli/output/terminal"
	"github.com/openkcm/krypton/cli/state"
	"github.com/openkcm/krypton/pkg/api/admin"
	"github.com/openkcm/krypton/pkg/model"
)

func selectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "select",
		Short: "Select a resource",
	}

	cmd.AddCommand(selectTenantCmd())

	return cmd
}

func selectTenantCmd() *cobra.Command {
	var interactive bool

	cmd := &cobra.Command{
		Use:   "tenant [id]",
		Short: "Select a tenant",
		Long:  "Select a tenant by ID, or use -i for interactive selection.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			stateStore, err := state.NewStore()
			if err != nil {
				return fmt.Errorf("failed to initialize state store: %w", err)
			}

			client, err := admin.NewClient(serverURL)
			if err != nil {
				return fmt.Errorf("failed to create client: %w", err)
			}

			var tenant model.Tenant

			switch {
			case len(args) == 1 && interactive:
				return errors.New("cannot use both tenant ID and --interactive flag")
			case len(args) == 1:
				tenant, err = getTenantByID(cmd.Context(), client, args[0])
			case interactive:
				tenant, err = selectTenantInteractive(cmd, client)
			default:
				return errors.New("tenant ID required (or use -i for interactive selection)")
			}

			if err != nil {
				return err
			}

			err = stateStore.Save(&state.State{
				Tenant: &state.TenantSelection{
					ID:   tenant.ID,
					Name: tenant.Name,
				},
			})
			if err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Selected tenant: %s (%s)\n", tenant.Name, tenant.ID)
			return nil
		},
	}

	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "interactive selection mode")

	return cmd
}

func getTenantByID(ctx context.Context, client *admin.Client, id string) (model.Tenant, error) {
	resp, err := client.GetTenant(ctx, admin.GetTenantRequest{ID: id})
	if err != nil {
		if errors.Is(err, admin.ErrTenantNotFound) {
			return model.Tenant{}, fmt.Errorf("tenant %q not found", id)
		}
		return model.Tenant{}, fmt.Errorf("failed to get tenant: %w", err)
	}
	return resp.Tenant, nil
}

func selectTenantInteractive(cmd *cobra.Command, client *admin.Client) (model.Tenant, error) {
	resp, err := client.ListTenants(cmd.Context(), admin.ListTenantsRequest{})
	if err != nil {
		return model.Tenant{}, fmt.Errorf("failed to list tenants: %w", err)
	}

	if len(resp.Tenants) == 0 {
		return model.Tenant{}, errors.New("no tenants found")
	}

	builder, err := output.From(resp.Tenants)
	if err != nil {
		return model.Tenant{}, fmt.Errorf("failed to format output: %w", err)
	}

	sel := terminal.Selector(cmd.OutOrStdout(), cmd.InOrStdin())
	idx, err := formatOutput(builder, false).Select(sel)
	if err != nil {
		if errors.Is(err, terminal.ErrInterrupt) {
			return model.Tenant{}, errors.New("selection cancelled")
		}
		return model.Tenant{}, fmt.Errorf("selection failed: %w", err)
	}

	return resp.Tenants[idx], nil
}
