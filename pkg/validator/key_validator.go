package validator

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

var (
	ErrEmptyTenantID              = errors.New("tenantId cannot be empty")
	ErrEmptyKeyKind               = errors.New("key kind cannot be empty")
	ErrInvalidKeyID               = errors.New("keyId is invalid")
	ErrEmptyName                  = errors.New("name cannot be empty")
	ErrInvalidTenantID            = errors.New("tenantId is invalid")
	ErrInvalidKeyKind             = errors.New("key kind is invalid")
	ErrInvalidParentKey           = errors.New("parent key is invalid")
	ErrTargetNotInTopology        = errors.New("target not present in topology")
	ErrTargetDoesNotManageKeyKind = errors.New("target does not manage the given key kind")
	ErrNonRootKey                 = errors.New("non root key must have a parent")
	ErrRootKeyParent              = errors.New("root key cannot have a parent")
	ErrParentInvalidState         = errors.New("parent key is not in a valid state")
	ErrParentKeyAdjacency         = errors.New("key is not adjacent to parent key")

	ErrFailedToGetTenant       = errors.New("failed to get tenant")
	ErrFailedToGetParentKeys   = errors.New("failed to get parent keys")
	ErrNoParentKeysToActivate  = errors.New("no parent keys to activate, key must have at least one parent key")
	ErrParentKeyNotInOrder     = errors.New("parent key is not in the correct order")
	ErrParentKeyTransientState = errors.New("parent key is in a transient state, please wait for the parent key to be completed")
	ErrKeyTransientState       = errors.New("key is in a transient state, please wait for the key to be completed")
	ErrNoParentKeyRelation     = errors.New("key has no parent key relation")

	ErrEmptyManagedBy        = errors.New("managed_by cannot be empty")
	ErrEmptyLifecycleState   = errors.New("lifecycle_state cannot be empty")
	ErrInvalidParentID       = errors.New("parent_id is invalid")
	ErrUnknownLifecycleState = errors.New("lifecycle_state is not a known state")
)

type AnnounceInput struct {
	TenantID   string
	KeyKind    string
	Name       string
	ParentID   string
	TargetName string
}

type UpsertKeyInput struct {
	TenantID       string
	KeyID          string
	Kind           string
	Name           string
	ManagedBy      string
	ParentID       string
	LifecycleState string
}

// ValidateKeyUpsert verifies the shape of an agent-side UpsertKey
// request. All fields are required.
func ValidateKeyUpsert(input UpsertKeyInput) error {
	switch {
	case !isValidUUID(input.TenantID):
		return ErrInvalidTenantID
	case !isValidUUID(input.KeyID):
		return ErrInvalidKeyID
	case input.Kind == "":
		return ErrEmptyKeyKind
	case input.Name == "":
		return ErrEmptyName
	case input.ManagedBy == "":
		return ErrEmptyManagedBy
	case !isValidUUID(input.ParentID):
		return ErrInvalidParentID
	case input.LifecycleState == "":
		return ErrEmptyLifecycleState
	}
	if !keylifecycle.IsKnown(model.KeyLifeCycleState(input.LifecycleState)) {
		return ErrUnknownLifecycleState
	}
	return nil
}

func ValidateKeyAnnounceRequest(input AnnounceInput, cfg config.RootConfig) error {
	switch {
	case !isValidUUID(input.TenantID):
		return ErrInvalidTenantID
	case input.Name == "":
		return ErrEmptyName
	case input.KeyKind == "":
		return ErrEmptyKeyKind
	}

	segment := cfg.Segment
	if input.TargetName != "" {
		topologySegment := cfg.Topology.GetSegmentByName(input.TargetName)
		if topologySegment == nil {
			return ErrTargetNotInTopology
		}

		segment = topologySegment.Segment
	}

	if !cfg.Hierarchy.SegmentContains(segment, model.KeyKind(input.KeyKind)) {
		return ErrTargetDoesNotManageKeyKind
	}

	return nil
}

// ValidateActivateRequest verifies that the tenant and key IDs of an
// activation request are valid UUIDs.
func ValidateActivateRequest(input ActivateInput) error {
	switch {
	case !isValidUUID(input.TenantID):
		return ErrEmptyTenantID
	case !isValidUUID(input.KeyID):
		return ErrInvalidKeyID
	}
	return nil
}

// ValidateTenant returns a transaction step that verifies the tenant
// exists.
func ValidateTenant(tenantID string) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		_, err := stores.Tenants.GetTenant(ctx, store.GetTenantQuery{ID: tenantID})
		return err
	}
}

// ValidateTransition returns a transaction step that verifies the target
// key exists and can transition to the requested life cycle state.
// If the key is already in the requested state, it returns no error.
func ValidateTransition(tenantID, keyID string, to model.KeyLifeCycleState) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		key, err := stores.Keys.GetKeyByID(ctx, keyID, tenantID)
		if err != nil {
			return err
		}
		if key.LifeCycleState != to {
			return keylifecycle.ValidateTransition(key.LifeCycleState, to)
		}
		return nil
	}
}

// ValidateKeyParents returns a transaction step that verifies every strict
// ancestor of the target key is active and has completed processing.
func ValidateKeyParents(tenantID, keyID string) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		parents, err := stores.Keys.GetParentKeys(ctx, store.GetParentKeysQuery{
			TenantID: tenantID,
			KeyID:    keyID,
		})
		if err != nil {
			return err
		}
		for _, parent := range parents.Keys {
			if parent.ID == keyID {
				continue
			}
			if parent.LifeCycleState != model.KeyLifeCycleActive ||
				parent.KeyProcessingState.Status != model.KeyProcessingCompleted {
				return ErrParentKeyTransientState
			}
		}
		return nil
	}
}

func ValidateKeyHierarchy(tenantID string, parentID *string, kind model.KeyKind, hierarchy spec.KeyHierarchy) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		keySpec, ok := hierarchy.FindKeySpec(kind)
		if !ok {
			return ErrInvalidKeyKind
		}

		isRoot := keySpec.Role == spec.KeyRoleRoot
		hasParent := parentID != nil

		switch {
		case isRoot && !hasParent:
			return nil
		case isRoot && hasParent:
			return ErrRootKeyParent
		case !isRoot && !hasParent:
			return ErrNonRootKey
		}

		parent, err := stores.Keys.GetKeyByID(ctx, *parentID, tenantID)
		if errors.Is(err, store.ErrKeyNotFound) {
			return ErrInvalidParentKey
		}
		if err != nil {
			return err
		}

		childIdx := hierarchy.IndexOf(kind)
		parentIdx := hierarchy.IndexOf(parent.Kind)
		if parentIdx < 0 || childIdx != parentIdx+1 {
			return ErrParentKeyAdjacency
		}

		return nil
	}
}
