package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/rootkey"
)

const testProviderCmdName = "test-provider"

func bindTestProviderCmd(opts *yokOptions) *cobra.Command {
	var instanceID, providerKeyID, accessToken string

	cmd := &cobra.Command{
		Use:   testProviderCmdName,
		Short: "Bind a test-provider key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runYOKOperation(cmd, opts, func(ctx context.Context, client rootkey.ServiceClient, tenantID, keyID string) error {
				_, err := client.CreateProvider(ctx, &rootkey.CreateProviderRequest{
					TenantId: tenantID,
					KeyId:    keyID,
					Provider: &rootkey.Provider{
						Provider: &rootkey.Provider_TestProvider{
							TestProvider: &rootkey.TestProvider{
								Config:      &rootkey.TestProviderConfig{InstanceId: instanceID},
								Auth:        &rootkey.TestProviderAuth{AccessToken: accessToken},
								ProviderKey: &rootkey.TestProviderKey{KeyId: providerKeyID},
							},
						},
					},
				})
				if err != nil {
					return fmt.Errorf("failed to bind test-provider key: %w", err)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&instanceID, "instance-id", "", "id of the test-provider instance")
	cmd.Flags().StringVar(&providerKeyID, "provider-key-id", "", "id of the test-provider key")
	cmd.Flags().StringVar(&accessToken, "access-token", "", "test-provider access token")
	_ = cmd.MarkFlagRequired("instance-id")
	_ = cmd.MarkFlagRequired("provider-key-id")
	_ = cmd.MarkFlagRequired("access-token")

	return cmd
}

func rotateTestProviderAuthCmd(opts *yokOptions) *cobra.Command {
	var accessToken string

	cmd := &cobra.Command{
		Use:   testProviderCmdName,
		Short: "Rotate test-provider authentication",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runYOKOperation(cmd, opts, func(ctx context.Context, client rootkey.ServiceClient, tenantID, keyID string) error {
				_, err := client.RotateAuth(ctx, &rootkey.RotateAuthRequest{
					TenantId: tenantID,
					KeyId:    keyID,
					Auth: &rootkey.ProviderAuth{
						Provider: &rootkey.ProviderAuth_TestProvider{
							TestProvider: &rootkey.TestProviderAuth{AccessToken: accessToken},
						},
					},
				})
				if err != nil {
					return fmt.Errorf("failed to rotate test-provider authentication: %w", err)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&accessToken, "access-token", "", "new test-provider access token")
	_ = cmd.MarkFlagRequired("access-token")
	return cmd
}

func rotateTestProviderKeyCmd(opts *yokOptions) *cobra.Command {
	var providerKeyID string

	cmd := &cobra.Command{
		Use:   testProviderCmdName,
		Short: "Rotate the test-provider key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runYOKOperation(cmd, opts, func(ctx context.Context, client rootkey.ServiceClient, tenantID, keyID string) error {
				_, err := client.RotateProviderKey(ctx, &rootkey.RotateProviderKeyRequest{
					TenantId: tenantID,
					KeyId:    keyID,
					ProviderKey: &rootkey.ProviderKey{
						Provider: &rootkey.ProviderKey_TestProvider{
							TestProvider: &rootkey.TestProviderKey{KeyId: providerKeyID},
						},
					},
				})
				if err != nil {
					return fmt.Errorf("failed to rotate test-provider key: %w", err)
				}
				return nil
			})
		},
	}

	cmd.Flags().StringVar(&providerKeyID, "provider-key-id", "", "id of the new test-provider key")
	_ = cmd.MarkFlagRequired("provider-key-id")
	return cmd
}
