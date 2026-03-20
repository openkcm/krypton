package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/pkg/api/admin"
)

func createCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a resource",
	}

	cmd.AddCommand(createTenantCmd())

	return cmd
}

func createTenantCmd() *cobra.Command {
	var name string
	var labels map[string]string

	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Create a new tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := admin.NewClient(serverURL)

			tenant, err := c.CreateTenant(cmd.Context(), admin.CreateTenantRequest{
				Name:   name,
				Labels: labels,
			})
			if err != nil {
				return fmt.Errorf("failed to create tenant: %w", err)
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(tenant)
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name of the tenant")
	cmd.Flags().StringToStringVar(&labels, "label", nil, "labels as key=value pairs (can be specified multiple times)")

	return cmd
}
