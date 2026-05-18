package model

import (
	"github.com/google/uuid"

	"github.com/openkcm/krypton/internal/clock"
)

type KeyKind string

type KeyState string

const (
	KeyStatePreActivation KeyState = "pre-activation"
	KeyStateActive        KeyState = "active"
	KeyStateSuspended     KeyState = "suspended"
	KeyStateDeactivated   KeyState = "deactivated"
	KeyStateCompromised   KeyState = "compromised"
	KeyStateDestroyed     KeyState = "destroyed"
)

type Key struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	TenantID  string         `json:"tenant_id"`
	Kind      KeyKind        `json:"kind"`
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
		Kind:      KeyKind(kind),
		ParentID:  parentID,
		ManagedBy: managedBy,
		Labels:    labels,
		State:     KeyStatePreActivation,
		CreatedAt: now,
		UpdatedAt: now,
	}
}
