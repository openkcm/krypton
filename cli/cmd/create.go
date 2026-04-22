package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/pkg/api/admin/v1"
	admingrpc "github.com/openkcm/krypton/pkg/api/admin/v1/proto"
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
			// TODO: insecure.NewCredentials is a temporary workaround until TLS is configured
			conn, err := grpc.NewClient(
				serverAddr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			if err != nil {
				return fmt.Errorf("failed to connect: %w", err)
			}
			defer conn.Close()

			client := admingrpc.NewServiceClient(conn)

			resp, err := client.CreateTenant(cmd.Context(), &admingrpc.CreateTenantRequest{
				Name:   name,
				Labels: labels,
			})
			if err != nil {
				return fmt.Errorf("failed to create tenant: %w", err)
			}

			tenant := admin.TenantFromProto(resp.GetTenant())

			builder, err := output.From(tenant)
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
