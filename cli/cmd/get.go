package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/pkg/api/admin"
)

func getCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a resource or a list of resources",
	}

	cmd.AddCommand(getTenantCmd())
	cmd.AddCommand(getTenantsCmd())

	return cmd
}

func getTenantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant <id>",
		Short: "Get a tenant by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := admin.NewClient(serverURL)

			resp, err := c.GetTenant(cmd.Context(), admin.GetTenantRequest{
				ID: args[0],
			})
			if err != nil {
				if errors.Is(err, admin.ErrTenantNotFound) {
					return fmt.Errorf("tenant %q not found", args[0])
				}
				return fmt.Errorf("failed to get tenant: %w", err)
			}

			return output.PrintTable(cmd.OutOrStdout(), resp)
		},
	}

	return cmd
}

func getTenantsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenants",
		Short: "Get all tenants",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := admin.NewClient(serverURL)

			resp, err := c.ListTenants(cmd.Context(), admin.ListTenantsRequest{})
			if err != nil {
				return fmt.Errorf("failed to list tenants: %w", err)
			}

			return output.PrintTable(cmd.OutOrStdout(), resp)
		},
	}

	return cmd
}
