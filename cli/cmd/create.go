package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/cli/output"
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
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Create a new tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := admin.NewClient(serverURL)

			resp, err := c.CreateTenant(cmd.Context(), admin.CreateTenantRequest{
				Name:   name,
				Labels: labels,
			})
			if err != nil {
				return fmt.Errorf("failed to create tenant: %w", err)
			}

			builder, err := output.From(resp.Tenant)
			if err != nil {
				return fmt.Errorf("failed to format output: %w", err)
			}

			return formatOutput(builder, asJSON).To(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "name of the tenant")
	cmd.Flags().StringToStringVar(&labels, "label", nil, "labels as key=value pairs (can be specified multiple times)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")

	return cmd
}
