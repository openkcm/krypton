package cmd

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/pkg/api/admin"
)

func getCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a resource",
	}

	cmd.AddCommand(getTenantCmd())

	return cmd
}

func getTenantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tenant <id>",
		Short: "Get a tenant by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := admin.NewClient(serverURL)

			tenant, err := c.GetTenant(cmd.Context(), admin.GetTenantRequest{
				ID: args[0],
			})
			if err != nil {
				if errors.Is(err, admin.ErrTenantNotFound) {
					return fmt.Errorf("tenant %q not found", args[0])
				}
				return fmt.Errorf("failed to get tenant: %w", err)
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(tenant)
		},
	}

	return cmd
}
