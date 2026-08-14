package cmd

import (
	"github.com/spf13/cobra"
)

func loginCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with the Krypton server using your credentials.",
	}
	cmd.AddCommand(noAuthLoginCmd())
	cmd.AddCommand(mtlsLoginCmd())
	return cmd
}
