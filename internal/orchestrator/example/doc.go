// Package example demonstrates how to drive the orchestrator package for a
// cascading key-activation workflow — the shape of Krypton's own use case.
//
// The scenario: activating a key hierarchy (root → child → grandchild) is a
// cascade. Each key can only be activated once its parent is active, so the
// activations must run in order. Modeled on the orchestrator backbone:
//
//   - A job group ([GroupTypeCascade]) holds one job per key in the hierarchy,
//     ordered root-first.
//   - Each job ([JobTypeActivateKey]) is handled by [ActivateKeyJobHandler]
//     (a orchestrator.JobHandler). It confirms the key is ready (parent active),
//     resolves the job into a single activation task targeted at the operator
//     that owns the key, and updates key state when the job terminates.
//   - The cascade group is handled by [CascadeGroupHandler]
//     (a orchestrator.JobGroupHandler), which observes the whole cascade
//     finishing.
//   - The activation task ([TaskTypeActivateKey]) is handled by
//     [ActivateKeyTaskHandler] (a orchestrator.TaskHandler). Its Handle body is
//     the actual activation work; whether that body is a state machine or a
//     single store write is the handler author's business — the orchestrator
//     just routes the task to it and runs it.
//
// [Setup] wires these three handlers into an orchestrator.Manager exactly as
// cmd/root would: an orbital repository backs job state, an optional
// target provider dials remote agent operators, and the in-process embedded
// operator (registered automatically because a task handler is present) runs
// activations for root-managed keys under the manager's LocalTarget.
//
// [NewCascade] builds and returns the job group a caller hands to
// Manager.PrepareJobGroup to kick the cascade off.
//
// The runnable Example in this package exercises the full handler contract
// (confirm → resolve → run task → job done) in-process against an in-memory
// [KeyStore], so it needs no Postgres or remote agents.
package example
