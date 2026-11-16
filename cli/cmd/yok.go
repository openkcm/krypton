package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
)

type yokOptions struct {
	tenantID string
	keyID    string
}

func yokCmd() *cobra.Command {
	opts := &yokOptions{}

	cmd := &cobra.Command{
		Use:   "yok",
		Short: "Manage bindings to keys you own outside Krypton",
	}

	cmd.PersistentFlags().StringVar(&opts.tenantID, "tenant-id", "", "id of the tenant (defaults to the selected tenant)")
	cmd.PersistentFlags().StringVar(&opts.keyID, "key-id", "", "id of the Krypton key")
	_ = cmd.MarkPersistentFlagRequired("key-id")

	cmd.AddCommand(bindYOKCmd(opts))
	cmd.AddCommand(rotateYOKAuthCmd(opts))
	cmd.AddCommand(rotateYOKKeyCmd(opts))
	cmd.AddCommand(unbindYOKCmd(opts))

	return cmd
}

func bindYOKCmd(opts *yokOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bind",
		Short: "Bind a Krypton key to your external key",
	}
	// TODO: Add AWS KMS support.
	cmd.AddCommand(bindTestProviderCmd(opts))
	return cmd
}

func rotateYOKAuthCmd(opts *yokOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate-auth",
		Short: "Rotate authentication for your external key provider",
	}
	// TODO: Add AWS KMS support.
	cmd.AddCommand(rotateTestProviderAuthCmd(opts))
	return cmd
}

func rotateYOKKeyCmd(opts *yokOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rotate-key",
		Short: "Rotate the external key used by your binding",
	}
	// TODO: Add AWS KMS support.
	cmd.AddCommand(rotateTestProviderKeyCmd(opts))
	return cmd
}

func unbindYOKCmd(opts *yokOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "unbind",
		Short: "Remove your external key binding",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runYOKOperation(cmd, opts, func(ctx context.Context, client rootkey.ServiceClient, tenantID, keyID string) error {
				_, err := client.RemoveProvider(ctx, &rootkey.RemoveProviderRequest{
					TenantId: tenantID,
					KeyId:    keyID,
				})
				if err != nil {
					return fmt.Errorf("failed to unbind provider: %w", err)
				}
				return nil
			})
		},
	}
}

func runYOKOperation(
	cmd *cobra.Command,
	opts *yokOptions,
	run func(context.Context, rootkey.ServiceClient, string, string) error,
) error {
	tenantID := opts.tenantID
	if tenantID == "" {
		selectedID, err := selectedTenantID()
		if err != nil {
			return fmt.Errorf("failed to get selected tenant: %w", err)
		}
		tenantID = selectedID
	}

	conn, err := newConnection(cmd.Context(), serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	return run(cmd.Context(), rootkey.NewServiceClient(conn), tenantID, opts.keyID)
}
