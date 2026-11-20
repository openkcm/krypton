package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
)

func suspendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suspend",
		Short: "Suspend a key",
	}
	cmd.AddCommand(suspendKeyCmd())
	return cmd
}

func suspendKeyCmd() *cobra.Command {
	var tenantID, keyID string
	var asJSON, isCascading bool

	cmd := &cobra.Command{
		Use:   keyCmd,
		Short: "Suspend an existing key by tenant and key ID",
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

			resp, err := client.SuspendKey(cmd.Context(), &keys.SuspendKeyRequest{
				TenantId:  tenantID,
				Id:        keyID,
				Cascading: isCascading,
			})
			if err != nil {
				return fmt.Errorf("failed to suspend key: %w", err)
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
	cmd.Flags().BoolVar(&isCascading, "cascading", false, "cascade suspension to all child keys (default: false)")
	_ = cmd.MarkFlagRequired("key-id")

	return cmd
}
