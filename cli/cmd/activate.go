package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
)

func activateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "activate",
		Short: "Activate a key",
	}
	cmd.AddCommand(activateKeyCmd())
	return cmd
}

type activatedKeyRow struct {
	Status bool
}

func activateKeyCmd() *cobra.Command {
	var tenantID, keyID string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   keyCmd,
		Short: "Activate an existing key by tenant and key ID",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				tID, err := selectedTenantID()
				if err != nil {
					return fmt.Errorf("failed to get selected tenant: %w", err)
				}
				tenantID = tID
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

			client := keys.NewKeyServiceClient(conn)

			_, err = client.ActivateKey(cmd.Context(), &keys.ActivateKeyRequest{
				TenantId: tenantID,
				Id:       keyID,
			})
			if err != nil {
				return fmt.Errorf("failed to activate key: %w", err)
			}

			builder, err := output.From(activatedKeyRow{Status: true})
			if err != nil {
				return fmt.Errorf("failed to format output: %w", err)
			}

			return formatOutput(builder, asJSON).To(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&keyID, "key-id", "", "id of the key")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "id of the tenant")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")
	_ = cmd.MarkFlagRequired("key-id")

	return cmd
}
