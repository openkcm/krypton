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
	case !isValidUUID(input.TenantID):
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
		topologySegment := v.topology.GetSegmentByName(input.TargetName)
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
// key exists, has completed processing, and can transition to the
// requested life cycle state.
func ValidateTransition(tenantID, keyID string, to model.KeyLifeCycleState) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		key, err := stores.Keys.GetKeyByID(ctx, keyID, tenantID)
		if err != nil {
			return err
		}
		if key.KeyProcessingState.Status != model.KeyProcessingCompleted {
			return ErrKeyTransientState
		}
		return keylifecycle.ValidateTransition(key.LifeCycleState, to)
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
