package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openkcm/krypton/cli/output"
	"github.com/openkcm/krypton/pkg/api/v1/proto/admin/jobs"
)

type jobGroupView struct {
	JobGroupID   string
	Type         string
	Status       string
	ErrorMessage string
}

type jobRow struct {
	JobID        string
	Type         string
	Status       string
	ErrorMessage string
}

func jobCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "job",
		Short: "Inspect orbital jobs",
	}
	cmd.AddCommand(jobStatusCmd())
	return cmd
}

func jobStatusCmd() *cobra.Command {
	var (
		groupID string
		asJSON  bool
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the status of a job group (e.g. a cascading activation)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			w := cmd.OutOrStdout()

			conn, err := newConnection(ctx, serverAddr)
			if err != nil {
				return fmt.Errorf("failed to connect: %w", err)
			}
			defer conn.Close()

			resp, err := jobs.NewJobServiceClient(conn).
				GetJobGroup(ctx, &jobs.GetJobGroupRequest{Id: groupID})
			if err != nil {
				return fmt.Errorf("failed to get job group: %w", err)
			}
			group := resp.GetJobGroup()
			if group == nil {
				return errors.New("server returned an empty job group")
			}

			view := jobGroupView{
				JobGroupID:   group.GetId(),
				Type:         group.GetType(),
				Status:       group.GetStatus(),
				ErrorMessage: group.GetErrorMessage(),
			}

			rows := make([]jobRow, 0, len(group.GetJobs()))
			for _, job := range group.GetJobs() {
				rows = append(rows, jobRow{
					JobID:        job.GetId(),
					Type:         job.GetType(),
					Status:       job.GetStatus(),
					ErrorMessage: job.GetErrorMessage(),
				})
			}

			if asJSON {
				combined := struct {
					JobGroup jobGroupView
					Jobs     []jobRow
				}{view, rows}
				b, err := output.From(combined)
				if err != nil {
					return err
				}
				return formatOutput(b, true).To(w)
			}

			gb, err := output.From(view)
			if err != nil {
				return err
			}
			if err := gb.As(output.KeyValue).To(w); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}

			jb, err := output.From(rows)
			if err != nil {
				return err
			}
			return formatOutput(jb, false).To(w)
		},
	}

	cmd.Flags().StringVar(&groupID, "id", "", "id of the job group")
	cmd.Flags().BoolVar(&asJSON, "json", false, "output in JSON format")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}
