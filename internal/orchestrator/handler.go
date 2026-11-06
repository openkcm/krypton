// Package orchestrator wraps the orbital library to give Krypton key
// operations a single reusable orchestration backbone.
//
// Orbital models work as a job that resolves into tasks, and runs each task as
// a request/response reconcile loop against an operator. This package lets a
// caller register handlers for that model and runs them:
//
//   - A [OrbitalTaskResolver] owns one job type: it confirms the job, resolves it into
//     tasks, and observes the job's terminal events.
//   - A [OrbitalJobGroupHandler] owns one job-group type and observes the group's
//     terminal events (the group is refetched with its jobs before dispatch).
//   - A [OrbitalTaskHandler] owns one task type. It runs in-process in an embedded
//     operator. Its Handle method IS orbital's handler contract, minus the type
//     switch this package performs for you. Whatever the handler does inside —
//     a multi-phase state machine or a single call — is the handler's business,
//     not this package's.
//
// # Adding an operation
//
//  1. Define the job, job-group, and task type constants for the operation.
//  2. Implement a [OrbitalTaskResolver] (and, for grouped work, a [OrbitalJobGroupHandler]).
//  3. Implement a [OrbitalTaskHandler] for each task type the operation runs on root.
//  4. Pass them to [New] via [OrbitalHandlers].
//  5. Register the orchestrator where the process is wired (a later PR moves the
//     running binaries onto this package).
//
// Label keys written to orbital must be prefixed "krypton/"; the "orbital/"
// prefix is reserved by the library.
package orchestrator

import (
	"context"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/pkg/model"
)

const (
	AnnounceKey   = "announce-key"
	ActivateKey   = "activate-key"
	SuspendKey    = "suspend-key"
	DeactivateKey = "deactivate-key"
)

type (
	HandlerConfig struct {
		handlerType string
		toState     model.KeyLifeCycleState
	}
)

func AnnounceHandlerConfig() HandlerConfig {
	return HandlerConfig{
		handlerType: AnnounceKey,
		toState:     model.KeyLifeCyclePreActivation,
	}
}

func ActivateHandlerConfig() HandlerConfig {
	return HandlerConfig{
		handlerType: ActivateKey,
		toState:     model.KeyLifeCycleActive,
	}
}

func SuspendHandlerConfig() HandlerConfig {
	return HandlerConfig{
		handlerType: SuspendKey,
		toState:     model.KeyLifeCycleSuspended,
	}
}

func DeactivateHandlerConfig() HandlerConfig {
	return HandlerConfig{
		handlerType: DeactivateKey,
		toState:     model.KeyLifeCycleDeactivated,
	}
}

// OrbitalTaskResolver owns the orbital lifecycle for a single Krypton job type.
type OrbitalTaskResolver interface {
	JobType() string
	ConfirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error)
	ResolveTasks(ctx context.Context, job orbital.Job, cursor orbital.TaskResolverCursor) (orbital.TaskResolverResult, error)
	OnJobDone(ctx context.Context, job orbital.Job) error
	OnJobFailed(ctx context.Context, job orbital.Job) error
	OnJobCanceled(ctx context.Context, job orbital.Job) error
}

// OrbitalJobGroupHandler observes the terminal events of a single Krypton job-group
// type. The group passed to each method is refetched from the repository so its
// Jobs slice is populated (orbital's event callback omits it).
type OrbitalJobGroupHandler interface {
	JobGroupType() string
	OnJobGroupDone(ctx context.Context, group orbital.JobGroup) error
	OnJobGroupFailed(ctx context.Context, group orbital.JobGroup) error
	OnJobGroupCanceled(ctx context.Context, group orbital.JobGroup) error
}

// OrbitalTaskHandler runs a single task type in-process in the embedded operator. Its
// Handle signature is orbital.HandlerFunc; the package routes tasks to the
// handler registered for req.TaskType and leaves the body entirely to it.
type OrbitalTaskHandler interface {
	TaskType() string
	Handle(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse)
}

// OrbitalHandlers bundles the handlers registered with a Manager.
type OrbitalHandlers struct {
	TaskResolvers []OrbitalTaskResolver
	GroupHandlers []OrbitalJobGroupHandler
	TaskHandlers  []OrbitalTaskHandler
}
