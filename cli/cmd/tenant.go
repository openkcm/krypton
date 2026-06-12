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

func getTenantCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "tenant <id>",
		Short: "Get a tenant by ID",
		Args:  cobra.ExactArgs(1),
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

			client := admin.NewTenantServiceClient(conn)

			resp, err := client.GetTenant(cmd.Context(), &admin.GetTenantRequest{
				Id: args[0],
			})
			if err != nil {
				if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
					return fmt.Errorf("tenant %q not found", args[0])
				}
				return fmt.Errorf("failed to get tenant: %w", err)
			}

			tenant := admin.TenantFromProto(resp.GetTenant())

			builder, err := output.From(tenant)
			if err != nil {
				return fmt.Errorf("failed to format output: %w", err)
			}

			return formatOutput(builder, asJSON).To(cmd.OutOrStdout())
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")

	return cmd
}

func getTenantsCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "tenants",
		Short: "Get tenants",
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

			client := admin.NewTenantServiceClient(conn)

			resp, err := client.ListTenants(cmd.Context(), &admin.ListTenantsRequest{})
			if err != nil {
				return fmt.Errorf("failed to list tenants: %w", err)
			}

			tenants := admin.TenantsFromProto(resp.GetTenants())

			builder, err := output.From(tenants)
			if err != nil {
				return fmt.Errorf("failed to format output: %w", err)
			}

			return formatOutput(builder, asJSON).To(cmd.OutOrStdout())
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")

	return cmd
}
