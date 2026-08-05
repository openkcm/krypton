package cmd

import (
	"github.com/spf13/cobra"
)

var serverAddr string

var rootCmd = &cobra.Command{
	Use:   "kr",
	Short: "A CLI tool for managing Krypton",
	Long:  `kr is a command-line interface for managing and interacting with the Krypton server.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&serverAddr, "server", "localhost:8080", "Krypton gRPC server address")

	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(createCmd())
	rootCmd.AddCommand(getCmd())
	rootCmd.AddCommand(selectCmd())
	rootCmd.AddCommand(announceCmd())
	rootCmd.AddCommand(activateCmd())
}
