// Package announcekey contains the manager-side (root) job handler and the
// operator-side (agent) task handler for the "announce-key" reconciliation
// flow.
//
// JobHandler runs on the root reconciler: it confirms a job, resolves it
// into a single task targeted at the agent, and updates the key's processing
// state when the job terminates.
//
// TaskHandler runs on the agent operator: it persists the announced key in
// the agent-local store. Errors are classified — corrupt task data and FK
// violations are terminal; transient errors are retried via orbital's
// default-continue semantics.
package announcekey

const (
	JobType  = "announce-key"
	TaskType = "announce-key"
)

// TaskData is the payload exchanged between the root job handler and the
// agent task handler. It is JSON-encoded into the orbital Job/Task data
// field.
//
// TODO: when a second handler is added, fields shared across handlers
// (e.g. Target, Labels, TenantID) should be lifted into a common
// envelope such as common.TaskInfo, leaving handler-specific fields
// (KeyID, Kind, Name, ParentID) on this struct.
type TaskData struct {
	KeyID    string            `json:"key_id"`
	TenantID string            `json:"tenant_id"`
	Kind     string            `json:"kind"`
	Name     string            `json:"name"`
	ParentID string            `json:"parent_id,omitempty"`
	Target   string            `json:"target"`
	Labels   map[string]string `json:"labels,omitempty"`
}
