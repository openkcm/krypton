// Package activatekey contains the root-side orchestration for cascading key
// activation. A single orbital job group activates a key and all its
// descendants: one job per hierarchy layer (root to leaf, run sequentially by
// orbital in slice order), one task per key (run in parallel within a layer on
// root's embedded operator).
//
// The per-key TaskHandler runs in-process on root. For a root-managed key it
// seals the material locally (the same chain admin ActivateKey used to run); for
// an agent-managed key it calls the owning agent's ActivateKey gRPC and records
// a metadata-only version row on root so the next layer can resolve its parent
// key version.
//
// Because orbital fails a job group as soon as one of its jobs fails, a failed
// layer stops the cascade: subsequent layers are never promoted.
package activatekey

const (
	// GroupType is the orbital job-group type for a cascading activation.
	GroupType = "activate-key"
	// JobType is the orbital job type for a single hierarchy layer.
	JobType = "activate-key-layer"
	// TaskType is the orbital task type for a single key.
	TaskType = "activate-key"
)

// LayerData is the job payload for one hierarchy layer. It is JSON-encoded into
// the orbital Job data field.
type LayerData struct {
	TenantID  string   `json:"tenant_id"`
	RootKeyID string   `json:"root_key_id"`
	KeyIDs    []string `json:"key_ids"`
}

// TaskData is the per-key task payload. The task handler loads the full key
// (and resolves the parent key version) from root's stores at run time, so the
// payload only needs to identify the key.
type TaskData struct {
	TenantID string `json:"tenant_id"`
	KeyID    string `json:"key_id"`
}
