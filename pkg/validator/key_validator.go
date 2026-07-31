package validator

import (
	"context"
	"errors"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type keyValidator struct {
	rootSegment spec.HierarchySegment
	tenants     store.Tenant
	keys        store.Key
	topology    spec.Topology
	hierarchy   spec.KeyHierarchy
}

var (
	ErrEmptyTenantID              = errors.New("tenantId cannot be empty")
	ErrEmptyKeyKind               = errors.New("key kind canot be empty")
	ErrInvalidKeyID               = errors.New("keyId is invalid")
	ErrEmptyName                  = errors.New("name canot be empty")
	ErrInvalidTenantID            = errors.New("tenantId is invalid")
	ErrInvalidKeyKind             = errors.New("key kind is invalid")
	ErrInvalidParentKey           = errors.New("parent key is invalid")
	ErrTargetNotInTopolgy         = errors.New("target not present in topology")
	ErrTargetDoesNotManageKeyKind = errors.New("target does not manage the given key kind")
	ErrNonRootKey                 = errors.New("non root key must have a parent")
	ErrRootKeyParent              = errors.New("root key cannot have a parent")
	ErrParentInvalidState         = errors.New("parent key is not in a valid state")
	ErrParentKeyAdjecency         = errors.New("key is not adjecent to parent key")

	ErrFailedToGetTenant       = errors.New("failed to get tenant")
	ErrFailedToGetParentKeys   = errors.New("failed to get parent keys")
	ErrNoParentKeysToActivate  = errors.New("no parent keys to activate, key must have at least one parent key")
	ErrParentKeyNotInOrder     = errors.New("parent key is not in the correct order")
	ErrParentKeyTransientState = errors.New("parent key is in a transient state, please wait for the parent key to be completed")
	ErrKeyTransientState       = errors.New("key is in a transient state, please wait for the key to be completed")
	ErrNoParentKeyRelation     = errors.New("key has no parent key relation")
)

func NewValidator(rootSegment spec.HierarchySegment, topology spec.Topology, hierarchy spec.KeyHierarchy, tenants store.Tenant, keys store.Key) KeyValidator {
	return &keyValidator{
		rootSegment: rootSegment,
		topology:    topology,
		hierarchy:   hierarchy,
		tenants:     tenants,
		keys:        keys,
	}
}

type AnnounceInput struct {
	TenantID   string
	KeyKind    string
	Name       string
	ParentID   string
	TargetName string
}

func (v *keyValidator) ValidateKeyAnnounce(ctx context.Context, input AnnounceInput) *ValidationError {
	ve := &ValidationError{
		code: Invalid,
	}

	switch {
	case input.TenantID == "":
		ve.err = ErrEmptyTenantID
		return ve
	case input.KeyKind == "":
		ve.err = ErrEmptyKeyKind
		return ve
	case input.Name == "":
		ve.err = ErrEmptyName
		return ve
	}

	if _, err := v.tenants.GetTenant(ctx, store.GetTenantQuery{ID: input.TenantID}); err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			ve.code, ve.err = FailedCondition, ErrInvalidTenantID
			return ve
		}
		ve.code, ve.err = Internal, err
		return ve
	}

	keySpec, ok := v.hierarchy.FindKeySpec(model.KeyKind(input.KeyKind))
	if !ok {
		ve.code, ve.err = Invalid, ErrInvalidKeyKind
		return ve
	}

	segment := v.rootSegment
	if input.TargetName != "" {
		topologySegment := v.topology.GetSegemntByName(input.TargetName)
		if topologySegment == nil {
			ve.code, ve.err = FailedCondition, ErrTargetNotInTopolgy
			return ve
		}

		segment = topologySegment.Segment
	}

	if !v.hierarchy.SegmentContains(segment, keySpec.Kind) {
		ve.code, ve.err = FailedCondition, ErrTargetDoesNotManageKeyKind
		return ve
	}

	if ok := v.isValidParent(ctx, input.ParentID, input.TenantID, keySpec, ve); !ok {
		return ve
	}

	return nil
}

// ValidateKeyActivate implements [KeyValidator].
func (v *keyValidator) ValidateKeyActivate(ctx context.Context, input ActivateInput) *ValidationError {
	ve := &ValidationError{
		code: Invalid,
	}

	switch {
	case input.TenantID == "":
		ve.err = ErrEmptyTenantID
		return ve
	case input.KeyID == "":
		ve.err = ErrInvalidKeyID
		return ve
	}

	if _, err := v.tenants.GetTenant(ctx, store.GetTenantQuery{ID: input.TenantID}); err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			ve.code, ve.err = FailedCondition, ErrInvalidTenantID
			return ve
		}
		ve.code, ve.err = Internal, ErrFailedToGetTenant
		return ve
	}

	parents, err := v.keys.GetParentKeys(ctx, store.GetParentKeysQuery{
		KeyID:    input.KeyID,
		TenantID: input.TenantID,
	})
	if err != nil {
		ve.code, ve.err = Internal, ErrFailedToGetParentKeys
		return ve
	}

	totalKs := len(parents.Keys)
	if totalKs < 2 {
		ve.code, ve.err = FailedCondition, ErrFailedToGetParentKeys
		return ve
	}

	for index, parent := range parents.Keys {
		if v.hierarchy.IndexOf(parent.Kind) != index {
			ve.code, ve.err = FailedCondition, ErrParentKeyNotInOrder
			return ve
		}
		isTargetKey := index+1 == totalKs
		if !isTargetKey {
			if parent.LifeCycleState != model.KeyLifeCycleActive || parent.KeyProcessingState.Status != model.KeyProcessingCompleted {
				ve.code, ve.err = FailedCondition, ErrParentKeyTransientState
				return ve
			}
			continue
		}
		// Target key: must be done processing and allow transition to active.
		if parent.KeyProcessingState.Status != model.KeyProcessingCompleted {
			ve.code, ve.err = FailedCondition, ErrKeyTransientState
			return ve
		}
		if err := keylifecycle.ValidateTransition(parent.LifeCycleState, model.KeyLifeCycleActive); err != nil {
			ve.code, ve.err = FailedCondition, err
			return ve
		}
	}
	return nil
}

func (v *keyValidator) isValidParent(ctx context.Context, parentID string, tenantID string, keySpec spec.KeySpec, ve *ValidationError) bool {
	if parentID == "" {
		if keySpec.Role != spec.KeyRoleRoot {
			ve.code, ve.err = Invalid, ErrNonRootKey
			return false
		}
		return true
	}

	if keySpec.Role == spec.KeyRoleRoot {
		ve.code, ve.err = Invalid, ErrRootKeyParent
		return false
	}

	parent, err := v.keys.GetKeyByID(ctx, parentID, tenantID)
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			ve.code, ve.err = FailedCondition, ErrInvalidParentKey
			return false
		}
		ve.code, ve.err = Internal, err
		return false
	}

	if parent.LifeCycleState != model.KeyLifeCycleActive {
		ve.code, ve.err = FailedCondition, ErrParentInvalidState
		return false
	}

	childIdx := v.hierarchy.IndexOf(keySpec.Kind)
	parentIdx := v.hierarchy.IndexOf(parent.Kind)
	if parentIdx < 0 || childIdx != parentIdx+1 {
		ve.code, ve.err = Invalid, ErrParentKeyAdjecency
		return false
	}

	return true
}
