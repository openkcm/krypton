package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin"
)

type keyTreeRow struct {
	Kind      string
	ID        string
	ParentID  string
	Name      string
	ManagedBy string
	Status    string
}

func newKeyTreeRow(k *admin.Key) keyTreeRow {
	return keyTreeRow{
		Kind:      k.GetKind(),
		ID:        k.GetId(),
		ParentID:  k.GetParentId(),
		Name:      k.GetName(),
		ManagedBy: k.GetManagedBy(),
		Status:    k.GetKeyProcessingState().GetStatus(),
	}
}

func getKeyParentsCmd() *cobra.Command {
	var keyID, tenantID string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "parent-keys",
		Short: "Get parent keys by tenant & key ID",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: insecure.NewCredentials is a temporary workaround until TLS is configured
			conn, err := grpc.NewClient(
				serverAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				return fmt.Errorf("failed to connect: %w", err)
			}
			defer conn.Close()

			client := admin.NewKeyServiceClient(conn)

			resp, err := client.GetParentKeys(cmd.Context(), &admin.GetParentKeysRequest{
				Id:       keyID,
				TenantId: tenantID,
			})
			if err != nil {
				if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
					return fmt.Errorf("parent keys for tenant:[%s] and key:[%s] not found", tenantID, keyID)
				}
				return fmt.Errorf("failed to get parent keys: %w", err)
			}

			ks := resp.GetKeys()
			treeRows := make([]keyTreeRow, 0, len(ks))
			for _, k := range ks {
				treeRows = append(treeRows, newKeyTreeRow(k))
			}

			builder, err := output.From(treeRows)
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
	_ = cmd.MarkFlagRequired("tenant-id")

	return cmd
}

func getKeyDescendantsCmd() *cobra.Command {
	var keyID, tenantID string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "descendant-keys",
		Short: "Get descendants by key & tenant ID",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: insecure.NewCredentials is a temporary workaround until TLS is configured
			conn, err := grpc.NewClient(
				serverAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				return fmt.Errorf("failed to connect: %w", err)
			}
			defer conn.Close()

			client := admin.NewKeyServiceClient(conn)

			resp, err := client.GetDescendantKeys(cmd.Context(), &admin.GetDescendantKeysRequest{
				Id:       keyID,
				TenantId: tenantID,
			})
			if err != nil {
				if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
					return fmt.Errorf("descendant keys for tenant:[%s] and key:[%s] not found", tenantID, keyID)
				}
				return fmt.Errorf("failed to get descendant keys: %w", err)
			}

			totalLen := 0
			trees := resp.GetKeyTree()
			for i := range trees {
				totalLen += len(trees[i].GetKeys()) + 1
			}

			treeRows := make([]keyTreeRow, 0, totalLen)
			for _, tree := range trees {
				for _, k := range tree.GetKeys() {
					treeRows = append(treeRows, newKeyTreeRow(k))
				}
				treeRows = append(treeRows, keyTreeRow{}) // add empty row for space between layers
			}

			builder, err := output.From(treeRows)
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
	_ = cmd.MarkFlagRequired("tenant-id")

	return cmd
}
