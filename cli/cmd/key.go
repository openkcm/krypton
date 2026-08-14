package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/keys"
	"github.com/openkcm/krypton/pkg/model"
)

const keyCmd = "key"

type keyRows struct {
	Keys   []keyRow
	Cursor string
}

type key struct {
	ID                 string
	Name               string
	TenantID           string
	Kind               model.KeyKind
	ParentID           *string
	ManagedBy          string
	Labels             model.Labels
	LifeCycleState     model.KeyLifeCycleState
	KeyProcessingState model.KeyProcessingState
	CreatedAt          clock.UnixNano
	UpdatedAt          clock.UnixNano
}

type keyRow struct {
	Kind           model.KeyKind
	ID             string
	ParentID       string
	Name           string
	LifeCycleState model.KeyLifeCycleState
	Labels         model.Labels
	ManagedBy      string
	Status         model.KeyProcessingStatus
}

func newKeyRow(k *keys.Key) keyRow {
	return keyRow{
		Kind:           model.KeyKind(k.GetKind()),
		ID:             k.GetId(),
		ParentID:       k.GetParentId(),
		Name:           k.GetName(),
		LifeCycleState: model.KeyLifeCycleState(k.GetLifeCycleState()),
		Labels:         k.GetLabels(),
		ManagedBy:      k.GetManagedBy(),
		Status:         model.KeyProcessingStatus(k.GetKeyProcessingState().GetStatus()),
	}
}

func newKey(k *keys.Key) key {
	mk := keys.KeyFromProto(k)
	return key{
		ID:                 mk.ID,
		Name:               mk.Name,
		TenantID:           mk.TenantID,
		Kind:               mk.Kind,
		ParentID:           mk.ParentID,
		ManagedBy:          mk.ManagedBy,
		Labels:             mk.Labels,
		LifeCycleState:     mk.LifeCycleState,
		KeyProcessingState: mk.KeyProcessingState,
		CreatedAt:          mk.CreatedAt,
		UpdatedAt:          mk.UpdatedAt,
	}
}

func getKeyCmd() *cobra.Command {
	var keyID, tenantID string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   keyCmd,
		Short: "Get a single key by its tenant ID and key ID",
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

			resp, err := client.GetKey(cmd.Context(), &keys.GetKeyRequest{
				Id:       keyID,
				TenantId: tenantID,
			})
			if err != nil {
				if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
					return fmt.Errorf("key for tenant:[%s] and key:[%s] not found", tenantID, keyID)
				}
				return fmt.Errorf("failed to get key: %w", err)
			}

			builder, err := output.From(newKey(resp.GetKey()))
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

func getKeyParentsCmd() *cobra.Command {
	var keyID, tenantID string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "parent-keys",
		Short: "Get parent keys by tenant & key ID",
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

			resp, err := client.GetParentKeys(cmd.Context(), &keys.GetParentKeysRequest{
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
			keyRows := make([]keyRow, 0, len(ks))
			for _, k := range ks {
				keyRows = append(keyRows, newKeyRow(k))
			}

			builder, err := output.From(keyRows)
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

func getKeyDescendantsCmd() *cobra.Command {
	var keyID, tenantID string
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "descendant-keys",
		Short: "Get descendants by key & tenant ID",
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

			resp, err := client.GetDescendantKeys(cmd.Context(), &keys.GetDescendantKeysRequest{
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
				totalLen += len(trees[i].GetKeys())
				if !asJSON {
					totalLen++
				}
			}

			keyRows := make([]keyRow, 0, totalLen)
			for _, tree := range trees {
				for _, k := range tree.GetKeys() {
					keyRows = append(keyRows, newKeyRow(k))
				}
				if !asJSON {
					keyRows = append(keyRows, keyRow{}) // add empty row for space between layers
				}
			}

			builder, err := output.From(keyRows)
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

func getKeysCmd() *cobra.Command {
	var tenantID, name, kind, lifeCycleState, managedBy, cursor, order string
	var labels map[string]string
	var limit int32
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "keys",
		Short: "List keys with optional filters",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if tenantID == "" {
				tID, err := selectedTenantID()
				if err != nil {
					return fmt.Errorf("failed to get selected tenant: %w", err)
				}
				tenantID = tID
			}

			isOrderByCreatedAtAsc := order == "asc"

			conn, err := newConnection(cmd.Context(), serverAddr)
			if err != nil {
				return fmt.Errorf("failed to connect: %w", err)
			}
			defer conn.Close()

			client := keys.NewKeyServiceClient(conn)

			resp, err := client.ListKeys(cmd.Context(), &keys.ListKeysRequest{
				TenantId:              tenantID,
				Name:                  name,
				Kind:                  kind,
				LifeCycleState:        lifeCycleState,
				ManagedBy:             managedBy,
				Labels:                labels,
				IsOrderByCreatedAtAsc: isOrderByCreatedAtAsc,
				Cursor:                cursor,
				Limit:                 limit,
			})

			if err != nil {
				if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
					return fmt.Errorf("keys for tenant:[%s] not found", tenantID)
				}
				return fmt.Errorf("failed to list keys: %w", err)
			}

			ks := resp.GetKeys()
			krs := keyRows{
				Keys:   make([]keyRow, 0, len(ks)),
				Cursor: resp.GetCursor(),
			}

			for _, k := range ks {
				krs.Keys = append(krs.Keys, newKeyRow(k))
			}

			var input any = krs
			if !asJSON {
				input = krs.Keys
			}

			builder, err := output.From(input)
			if err != nil {
				return fmt.Errorf("failed to format output: %w", err)
			}
			err = formatOutput(builder, asJSON).To(cmd.OutOrStdout())

			if asJSON || err != nil || krs.Cursor == "" {
				return err
			}

			_, err = fmt.Fprintf(cmd.OutOrStdout(), "\nCursor: %s\n", krs.Cursor)
			return err
		},
	}
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Tenant identifier to filter keys by")
	cmd.Flags().StringVar(&name, "name", "", "Filter keys by name")
	cmd.Flags().StringVar(&kind, "kind", "", "Filter keys by kind")
	cmd.Flags().StringVar(&lifeCycleState, "lifecycle-state", "", "Filter keys by lifecycle state")
	cmd.Flags().StringVar(&managedBy, "managed-by", "", "Filter keys by managing entity")
	cmd.Flags().StringVar(&cursor, "cursor", "", "Pagination cursor from a previous response")
	cmd.Flags().StringToStringVar(&labels, "labels", nil, "Filter by labels as key=value pairs (repeatable)")
	cmd.Flags().StringVar(&order, "order", "desc", "Sort order by creation time: asc or desc")
	cmd.Flags().Int32Var(&limit, "limit", 0, "Maximum number of keys to return (0 for no limit)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")

	return cmd
}
