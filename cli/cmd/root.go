package cmd

import (
	"github.com/spf13/cobra"
)

var serverURL string

var rootCmd = &cobra.Command{
	Use:   "kr",
	Short: "A CLI tool for managing Krypton",
	Long:  `kr is a command-line interface for managing and interacting with the Krypton server.`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "http://localhost:8080", "Krypton server URL")

	rootCmd.AddCommand(loginCmd())
	rootCmd.AddCommand(createCmd())
	rootCmd.AddCommand(getCmd())
}
