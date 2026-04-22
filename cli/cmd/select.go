package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/cli/output/terminal"
	"github.com/openkcm/krypton/cli/state"
	"github.com/openkcm/krypton/pkg/api/admin/v1"
	admingrpc "github.com/openkcm/krypton/pkg/api/admin/v1/proto"
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

			// TODO: insecure.NewCredentials is a temporary workaround until TLS is configured
			conn, err := grpc.NewClient(
				serverAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				return fmt.Errorf("failed to connect: %w", err)
			}
			defer conn.Close()

			client := admingrpc.NewServiceClient(conn)

			var tenant *admingrpc.Tenant

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
					ID:   tenant.GetId(),
					Name: tenant.GetName(),
				},
			})
			if err != nil {
				return fmt.Errorf("failed to save state: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Selected tenant: %s (%s)\n", tenant.GetName(), tenant.GetId())
			return nil
		},
	}

	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "interactive selection mode")

	return cmd
}

func getTenantByID(ctx context.Context, client admingrpc.ServiceClient, id string) (*admingrpc.Tenant, error) {
	resp, err := client.GetTenant(ctx, &admingrpc.GetTenantRequest{
		Id: id,
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return nil, fmt.Errorf("tenant %q not found", id)
		}
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}
	return resp.GetTenant(), nil
}

func selectTenantInteractive(cmd *cobra.Command, client admingrpc.ServiceClient) (*admingrpc.Tenant, error) {
	resp, err := client.ListTenants(cmd.Context(), &admingrpc.ListTenantsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}

	if len(resp.GetTenants()) == 0 {
		return nil, errors.New("no tenants found")
	}

	tenants := admin.TenantsFromProto(resp.GetTenants())

	builder, err := output.From(tenants)
	if err != nil {
		return nil, fmt.Errorf("failed to format output: %w", err)
	}

	sel := terminal.Selector(cmd.OutOrStdout(), cmd.InOrStdin())
	idx, err := formatOutput(builder, false).Select(sel)
	if err != nil {
		if errors.Is(err, terminal.ErrInterrupt) {
			return nil, errors.New("selection cancelled")
		}
		return nil, fmt.Errorf("selection failed: %w", err)
	}

	return resp.GetTenants()[idx], nil
}
