package cmd

import (
	"github.com/spf13/cobra"
)

func getCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "Get a resource",
	}

	cmd.AddCommand(getTenantCmd())
	cmd.AddCommand(getTenantsCmd())
	cmd.AddCommand(getKeyParentsCmd())
	cmd.AddCommand(getKeyDescendantsCmd())

	return cmd
}
