package model

import (
	"github.com/google/uuid"

	"github.com/openkcm/krypton/internal/clock"
)

type KeyState string

const (
	KeyStatePending   KeyState = "pending"
	KeyStateAnnounced KeyState = "announced"
	KeyStateFailed    KeyState = "failed"
)

type Key struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	TenantID  string         `json:"tenant_id"`
	Kind      string         `json:"kind"`
	ParentID  *string        `json:"parent_id"`
	ManagedBy string         `json:"managed_by"`
	Labels    Labels         `json:"labels"`
	State     KeyState       `json:"state"`
	CreatedAt clock.UnixNano `json:"created_at"`
	UpdatedAt clock.UnixNano `json:"updated_at"`
}

func NewKey(tenantID, name string, kind string, parentID *string, managedBy string, labels Labels) Key {
	now := clock.Now()
	return Key{
		ID:        uuid.NewString(),
		Name:      name,
		TenantID:  tenantID,
		Kind:      kind,
		ParentID:  parentID,
		ManagedBy: managedBy,
		Labels:    labels,
		State:     KeyStatePending,
		CreatedAt: now,
		UpdatedAt: now,
	}
}
