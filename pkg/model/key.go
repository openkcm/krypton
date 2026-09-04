package model

import (
	"iter"
	"slices"
	"uuid"

	"github.com/openkcm/krypton/internal/clock"
)

type KeyKind string

type KeyLifeCycleState string

const (
	KeyLifeCyclePreActivation KeyLifeCycleState = "pre-activation"
	KeyLifeCycleActive        KeyLifeCycleState = "active"
	KeyLifeCycleSuspended     KeyLifeCycleState = "suspended"
	KeyLifeCycleDeactivated   KeyLifeCycleState = "deactivated"
	KeyLifeCycleCompromised   KeyLifeCycleState = "compromised"
	KeyLifeCycleDestroyed     KeyLifeCycleState = "destroyed"
)

// KeyProcessingState captures the state of asynchronous work performed on a
// key (e.g. announce-key reconciliation).
type KeyProcessingState struct {
	Status KeyProcessingStatus `json:"status"`
	JobID  string              `json:"job_id,omitempty"`
}

type KeyProcessingStatus string

const (
	KeyProcessingPending    KeyProcessingStatus = "pending"
	KeyProcessingInProgress KeyProcessingStatus = "in-progress"
	KeyProcessingCompleted  KeyProcessingStatus = "completed"
	KeyProcessingFailed     KeyProcessingStatus = "failed"
)

func (s KeyProcessingStatus) IsOneOf(statuses ...KeyProcessingStatus) bool {
	return slices.Contains(statuses, s)
}

type Key struct {
	ID                 string             `json:"id"`
	Name               string             `json:"name"`
	TenantID           string             `json:"tenant_id"`
	Kind               KeyKind            `json:"kind"`
	ParentID           *string            `json:"parent_id"`
	ManagedBy          string             `json:"managed_by"`
	Labels             Labels             `json:"labels"`
	LifeCycleState     KeyLifeCycleState  `json:"life_cycle_state"`
	KeyProcessingState KeyProcessingState `json:"key_processing_state"`
	CreatedAt          clock.UnixNano     `json:"created_at"`
	UpdatedAt          clock.UnixNano     `json:"updated_at"`
}

func (k *Key) IsSame(other *Key) bool {
	if k == nil || other == nil {
		return false
	}
	if !equalStringPtr(k.ParentID, other.ParentID) {
		return false
	}

	return k.Name == other.Name &&
		k.TenantID == other.TenantID &&
		k.ManagedBy == other.ManagedBy &&
		k.Kind == other.Kind
}

func equalStringPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// KeyTree represents a hierarchical structure of keys, where each inner
// slice represents a layer of keys in the hierarchy.
type KeyTree [][]Key

// KeyTreeTraverser defines methods for traversing a KeyTree in different orders.
type KeyTreeTraverser interface {
	// IterKeysByLayerAsc iterates the keys layer by layer in ascending order (from root to leaf).
	IterKeysByLayerAsc() iter.Seq[[]Key]
	// IterKeysByLayerDsc iterates the keys layer by layer in descending order (from leaf to root).
	IterKeysByLayerDsc() iter.Seq[[]Key]
	// IterLayerAsc iterates the key kinds layer by layer in ascending order (from root to leaf).
	IterLayerAsc() iter.Seq[KeyKind]
	// IterLayerDsc iterates the key kinds layer by layer in descending order (from leaf to root).
	IterLayerDsc() iter.Seq[KeyKind]
}

func NewKey(tenantID, name string, kind string, parentID *string, managedBy string, labels Labels) Key {
	now := clock.Now()
	return Key{
		ID:                 uuid.New().String(),
		Name:               name,
		TenantID:           tenantID,
		Kind:               KeyKind(kind),
		ParentID:           parentID,
		ManagedBy:          managedBy,
		Labels:             labels,
		LifeCycleState:     KeyLifeCyclePreActivation,
		KeyProcessingState: KeyProcessingState{Status: KeyProcessingPending},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

var _ KeyTreeTraverser = KeyTree{}

// IterKeysByLayerAsc iterates the keys layer by layer in ascending order (from root to leaf).
func (kt KeyTree) IterKeysByLayerAsc() iter.Seq[[]Key] {
	return func(yield func([]Key) bool) {
		for _, layer := range kt {
			if !yield(layer) {
				return
			}
		}
	}
}

// IterKeysByLayerDsc iterates the keys layer by layer in descending order (from leaf to root).
func (kt KeyTree) IterKeysByLayerDsc() iter.Seq[[]Key] {
	return func(yield func([]Key) bool) {
		for _, layer := range slices.Backward(kt) {
			if !yield(layer) {
				return
			}
		}
	}
}

// IterLayerAsc iterates the key kinds layer by layer in ascending order (from root to leaf).
func (kt KeyTree) IterLayerAsc() iter.Seq[KeyKind] {
	return func(yield func(KeyKind) bool) {
		for _, layer := range kt {
			if len(layer) == 0 {
				continue
			}
			if !yield(layer[0].Kind) {
				return
			}
		}
	}
}

// IterLayerDsc iterates the key kinds layer by layer in descending order (from leaf to root).
func (kt KeyTree) IterLayerDsc() iter.Seq[KeyKind] {
	return func(yield func(KeyKind) bool) {
		for _, layer := range slices.Backward(kt) {
			if len(layer) == 0 {
				continue
			}
			if !yield(layer[0].Kind) {
				return
			}
		}
	}
}
