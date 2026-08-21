package cmd

import (
	"encoding/json/v2"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/pkg/authn"
	"github.com/openkcm/krypton/pkg/authn/provider"
	"github.com/openkcm/krypton/pkg/authn/store"
)

func mtlsLoginCmd() *cobra.Command {
	var keyPath, certPath, caPath string
	var authProvider authn.Provider
	var authStore authn.Store

	cmd := &cobra.Command{
		Use:   "mtls",
		Short: "Login to Krypton",
		Long:  "Authenticate with the Krypton server to obtain access using mutual TLS.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			authProvider = &provider.MTLS{}
			fs, err := store.NewFS()
			if err != nil {
				return err
			}
			authStore = fs

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			b, err := json.Marshal(&provider.MTLSCredentialsValue{
				PublicCertPath: certPath,
				PrivateKeyPath: keyPath,
				CaCertPath:     caPath,
			})
			if err != nil {
				return fmt.Errorf("failed to marshal credentials value: %w", err)
			}

			creds := &authn.Credentials{
				Type:  authn.MTLS,
				Value: b,
			}

			tkn, err := authProvider.Verify(ctx, creds)
			if err != nil {
				return err
			}

			err = authStore.Store(ctx, tkn)
			if err != nil {
				return err
			}

			fmt.Println("Login successful.")
			return nil
		},
	}
	cmd.Flags().StringVar(&certPath, "cert", "", "Public certificate path")
	cmd.Flags().StringVar(&keyPath, "key", "", "Private key path")
	cmd.Flags().StringVar(&caPath, "ca", "", "CA certificate path")
	_ = cmd.MarkFlagRequired("cert")
	_ = cmd.MarkFlagRequired("key")
	_ = cmd.MarkFlagRequired("ca")

	return cmd
}
