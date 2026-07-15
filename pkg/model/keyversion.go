package model

import "github.com/openkcm/krypton/internal/clock"

// KeyVersionProcessingState represents the processing state of a key version.
type KeyVersionProcessingState string

const (
	KeyVersionUsable     KeyVersionProcessingState = "usable"
	KeyVersionReWrapping KeyVersionProcessingState = "re-wrapping"
)

// KeyVersion tracks both the version (which key material is used) and the
// revision (which wrapping of that material is current). A KeyVersion is
// uniquely identified by the composite key (TenantID, KeyID, Version, Revision).
type KeyVersion struct {
	TenantID         string                    `json:"tenant_id"`
	KeyID            string                    `json:"key_id"`
	Version          string                    `json:"version"`
	Revision         int                       `json:"revision"`
	ParentKeyID      *string                   `json:"parent_key_id,omitempty"`
	ParentKeyVersion *string                   `json:"parent_key_version,omitempty"`
	LifeCycleState   KeyLifeCycleState         `json:"life_cycle_state"`
	ProcessingState  KeyVersionProcessingState `json:"processing_state"`
	CreatedAt        clock.UnixNano            `json:"created_at"`
	UpdatedAt        clock.UnixNano            `json:"updated_at"`
}
