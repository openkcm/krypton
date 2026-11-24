package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
)

func compromiseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mark-compromised",
		Short: "Mark a key as compormised",
	}
	cmd.AddCommand(compromiseKeyCmd())
	return cmd
}

func compromiseKeyCmd() *cobra.Command {
	var tenantID, keyID string
	var asJSON, isCascading bool

	cmd := &cobra.Command{
		Use:   keyCmd,
		Short: "Mark as compromised an existing key by tenant and key ID",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				tID, err := selectedTenantID()
				if err != nil {
					return fmt.Errorf("failed to get selected tenant: %w", err)
				}
				tenantID = tID
			}

			conn, err := newConnection(cmd.Context(), serverAddr)
			if err != nil {
				return fmt.Errorf("failed to connect: %w", err)
			}
			defer conn.Close()

			client := keys.NewKeyServiceClient(conn)

			resp, err := client.CompromiseKey(cmd.Context(), &keys.CompromiseKeyRequest{
				TenantId:  tenantID,
				Id:        keyID,
				Cascading: isCascading,
			})
			if err != nil {
				return fmt.Errorf("failed to compromise key: %w", err)
			}

			builder, err := output.From(jobGroup{ID: resp.GetJobGroupId()})
			if err != nil {
				return fmt.Errorf("failed to format output: %w", err)
			}

			return formatOutput(builder, asJSON).To(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&keyID, "key-id", "", "id of the key")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "id of the tenant")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")
	cmd.Flags().BoolVar(&isCascading, "cascading", false, "cascade compromising to all child keys (default: false)")
	_ = cmd.MarkFlagRequired("key-id")

	return cmd
}
