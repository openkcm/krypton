package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/cli/state"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
)

func announceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "announce",
		Short: "Announce a key",
	}

	cmd.AddCommand(announceKeyCmd())

	return cmd
}

type announcedKeyRow struct {
	ID        string
	Kind      string
	Name      string
	ParentID  string
	ManagedBy string
	Labels    model.Labels
	Status    string
	JobID     string
}

func newAnnouncedKeyRow(k *keys.Key) announcedKeyRow {
	return announcedKeyRow{
		ID:        k.GetId(),
		Kind:      k.GetKind(),
		Name:      k.GetName(),
		ParentID:  k.GetParentId(),
		ManagedBy: k.GetManagedBy(),
		Labels:    model.Labels(k.GetLabels()),
		Status:    k.GetKeyProcessingState().GetStatus(),
		JobID:     k.GetKeyProcessingState().GetJobId(),
	}
}

func announceKeyCmd() *cobra.Command {
	var kind, name, parent, targetName string
	var labels map[string]string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "key",
		Short: "Announce a new key in the selected tenant's hierarchy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			tenantID, err := selectedTenantID()
			if err != nil {
				return err
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

			resp, err := client.AnnounceKey(cmd.Context(), &keys.AnnounceKeyRequest{
				TenantId:   tenantID,
				Kind:       kind,
				Name:       name,
				ParentId:   parent,
				TargetName: targetName,
				Labels:     labels,
			})
			if err != nil {
				return fmt.Errorf("failed to announce key: %w", err)
			}

			builder, err := output.From(newAnnouncedKeyRow(resp.GetKey()))
			if err != nil {
				return fmt.Errorf("failed to format output: %w", err)
			}

			return formatOutput(builder, asJSON).To(cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&kind, "kind", "", "kind of the key in the hierarchy (e.g. K0, K1)")
	cmd.Flags().StringVar(&name, "name", "", "name of the key")
	cmd.Flags().StringVar(&parent, "parent", "", "id of the parent key (omit for root keys)")
	cmd.Flags().StringVar(&targetName, "target-name", "", "name of the target agent (omit to announce on root)")
	cmd.Flags().StringToStringVar(&labels, "label", nil, "labels as key=value pairs (can be specified multiple times)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("name")

	return cmd
}

func selectedTenantID() (string, error) {
	stateStore, err := state.NewStore()
	if err != nil {
		return "", fmt.Errorf("failed to initialize state store: %w", err)
	}

	st, err := stateStore.Load()
	if err != nil {
		if errors.Is(err, state.ErrStateNotFound) {
			return "", errors.New("no tenant selected. Run 'kr select tenant' to choose a tenant")
		}
		return "", fmt.Errorf("failed to load state: %w", err)
	}

	if st.Tenant == nil {
		return "", errors.New("no tenant selected. Run 'kr select tenant' to choose a tenant")
	}

	return st.Tenant.ID, nil
}
