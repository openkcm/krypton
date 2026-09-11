// Package orchestrator wraps the orbital library to give Krypton key
// operations a single reusable orchestration backbone.
//
// Orbital models work as a job that resolves into tasks, and runs each task as
// a request/response reconcile loop against an operator. This package lets a
// caller register handlers for that model and runs them:
//
//   - A [JobHandler] owns one job type: it confirms the job, resolves it into
//     tasks, and observes the job's terminal events.
//   - A [JobGroupHandler] owns one job-group type and observes the group's
//     terminal events (the group is refetched with its jobs before dispatch).
//   - A [TaskHandler] owns one task type. It runs in-process in an embedded
//     operator. Its Handle method IS orbital's handler contract, minus the type
//     switch this package performs for you. Whatever the handler does inside —
//     a multi-phase state machine or a single call — is the handler's business,
//     not this package's.
//
// # Adding an operation
//
//  1. Define the job, job-group, and task type constants for the operation.
//  2. Implement a [JobHandler] (and, for grouped work, a [JobGroupHandler]).
//  3. Implement a [TaskHandler] for each task type the operation runs on root.
//  4. Pass them to [New] via [Handlers].
//  5. Register the orchestrator where the process is wired (a later PR moves the
//     running binaries onto this package).
//
// Label keys written to orbital must be prefixed "krypton/"; the "orbital/"
// prefix is reserved by the library.
package orchestrator

import (
	"context"

	"github.com/openkcm/orbital"
)

// JobHandler owns the orbital lifecycle for a single Krypton job type.
type JobHandler interface {
	JobType() string
	ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error)
	ResolveTasks(ctx context.Context, job orbital.Job, cursor orbital.TaskResolverCursor) (orbital.TaskResolverResult, error)
	OnJobDone(ctx context.Context, job orbital.Job) error
	OnJobFailed(ctx context.Context, job orbital.Job) error
	OnJobCanceled(ctx context.Context, job orbital.Job) error
}

// JobGroupHandler observes the terminal events of a single Krypton job-group
// type. The group passed to each method is refetched from the repository so its
// Jobs slice is populated (orbital's event callback omits it).
type JobGroupHandler interface {
	JobGroupType() string
	OnJobGroupDone(ctx context.Context, group orbital.JobGroup) error
	OnJobGroupFailed(ctx context.Context, group orbital.JobGroup) error
	OnJobGroupCanceled(ctx context.Context, group orbital.JobGroup) error
}

// TaskHandler runs a single task type in-process in the embedded operator. Its
// Handle signature is orbital.HandlerFunc; the package routes tasks to the
// handler registered for req.TaskType and leaves the body entirely to it.
type TaskHandler interface {
	TaskType() string
	Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse)
}

// Handlers bundles the handlers registered with a Manager.
type Handlers struct {
	Jobs   []JobHandler
	Groups []JobGroupHandler
	Tasks  []TaskHandler
}
