package model

import (
	"fmt"

	"github.com/openkcm/krypton/internal/clock"
)

// KeyVersionProcessingState represents the processing state of a key version.
type KeyVersionProcessingState string

const (
	KeyVersionUsable     KeyVersionProcessingState = "usable"
	KeyVersionReWrapping KeyVersionProcessingState = "re-wrapping"
	KeyVersionActivating KeyVersionProcessingState = "activating"
)

var allKeyVersionStates = map[KeyVersionProcessingState]struct{}{
	KeyVersionUsable:     {},
	KeyVersionReWrapping: {},
	KeyVersionActivating: {},
}

// KeyVersion tracks both the version (which key material is used) and the
// revision (which wrapping of that material is current). A KeyVersion is
// uniquely identified by the composite key (TenantID, KeyID, Version, Revision).
type KeyVersion struct {
	TenantID         string                    `json:"tenant_id"`
	KeyID            string                    `json:"key_id"`
	Version          int                       `json:"version"`
	Revision         int                       `json:"revision"`
	ParentKeyID      *string                   `json:"parent_key_id,omitempty"`
	ParentKeyVersion *int                      `json:"parent_key_version,omitempty"`
	LifeCycleState   KeyLifeCycleState         `json:"life_cycle_state"`
	ProcessingState  KeyVersionProcessingState `json:"processing_state"`
	CreatedAt        clock.UnixNano            `json:"created_at"`
	UpdatedAt        clock.UnixNano            `json:"updated_at"`
}

func NewKeyVersion(tenantID, keyID string, version int, parentKeyID *string, parentKeyVersion *int) KeyVersion {
	now := clock.Now()
	return KeyVersion{
		TenantID:         tenantID,
		KeyID:            keyID,
		Version:          version,
		Revision:         1,
		ParentKeyID:      parentKeyID,
		ParentKeyVersion: parentKeyVersion,
		LifeCycleState:   KeyLifeCycleActive,
		ProcessingState:  KeyVersionUsable,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func (kv *KeyVersion) AAD() []byte {
	if kv == nil {
		return nil
	}
	return fmt.Appendf(nil, "%s:%s:%d:%d", kv.TenantID, kv.KeyID, kv.Version, kv.Revision)
}

func IsKnownKeyVersionState(state string) bool {
	_, ok := allKeyVersionStates[KeyVersionProcessingState(state)]
	return ok
}
