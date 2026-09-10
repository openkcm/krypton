package example_test

import (
	"context"
	"fmt"
	"log/slog"
	"uuid"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/internal/orchestrator/example"
)

// Example drives the full handler contract for a three-key cascade
// (root → k1 → k2) in-process, without orbital's Postgres-backed manager or any
// remote agent. It shows the two things the orchestrator guarantees: the job
// handler gates activation on cascade order, and the task handler runs the work
// once a job is confirmed and resolved.
func Example() {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler) // keep example output clean

	// One store stands in for the root and every operator in this single process.
	store := example.NewKeyStore("root", "k1", "k2")
	jobH := example.NewActivateKeyJobHandler(store, log)
	taskH := example.NewActivateKeyTaskHandler(store, log)

	// The hierarchy to activate, in cascade order. Target "local" would be the
	// manager's LocalTarget() in a wired-up process.
	group, err := example.NewCascade([]example.KeySpec{
		{ID: "root", Target: "local"},
		{ID: "k1", ParentID: "root", Target: "local"},
		{ID: "k2", ParentID: "k1", Target: "local"},
	})
	if err != nil {
		panic(err)
	}

	completeType := orbital.CompleteJobConfirmer().Type()
	fmt.Println("before cascade:", store)

	// Confirming k1 before root is active is gated: the job handler asks orbital
	// to retry later rather than activating out of order.
	if res, _ := jobH.ConfirmJob(ctx, group.Jobs[1]); res.Type() != completeType {
		fmt.Println("gate check k1 (root inactive): retry-later")
	}

	// Reconcile each job in order: confirm → resolve → run the task on the
	// operator → record the job done.
	for _, job := range group.Jobs {
		res, err := jobH.ConfirmJob(ctx, job)
		if err != nil {
			panic(err)
		}
		if res.Type() != completeType {
			fmt.Printf("activate %s: gated\n", job.ExternalID)
			continue
		}

		// ResolveTasks emits one task carrying the job's data; the embedded
		// operator runs it via the task handler. We execute it inline here.
		if _, err := jobH.ResolveTasks(ctx, job, ""); err != nil {
			panic(err)
		}
		resp := orbital.ExecuteHandler(ctx, taskH.Handle, orbital.TaskRequest{
			TaskID: uuid.New(),
			Type:   example.TaskTypeActivateKey,
			Data:   job.Data,
		})

		if err := jobH.OnJobDone(ctx, job); err != nil {
			panic(err)
		}
		state, _ := store.State(job.ExternalID)
		fmt.Printf("activate %s: task=%s -> %s\n", job.ExternalID, resp.Status, state)
	}

	fmt.Println("after cascade:", store)

	// Orbital fires the group handler once the whole cascade terminates.
	if err := example.NewCascadeGroupHandler(log).OnJobGroupDone(ctx, group); err != nil {
		panic(err)
	}
	fmt.Printf("cascade group: %d keys\n", len(group.Jobs))

	// Output:
	// before cascade: k1=INACTIVE k2=INACTIVE root=INACTIVE
	// gate check k1 (root inactive): retry-later
	// activate root: task=DONE -> ACTIVE
	// activate k1: task=DONE -> ACTIVE
	// activate k2: task=DONE -> ACTIVE
	// after cascade: k1=ACTIVE k2=ACTIVE root=ACTIVE
	// cascade group: 3 keys
}
