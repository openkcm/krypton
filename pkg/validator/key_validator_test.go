package validator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"

	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

var validUUID = uuid.NewString()
var invalidUUID = "invalid-uuid"

type stubTenantStore struct {
	store.Tenant

	getTenant func(ctx context.Context, q store.GetTenantQuery) (store.GetTenantResult, error)
}

func (s *stubTenantStore) GetTenant(ctx context.Context, q store.GetTenantQuery) (store.GetTenantResult, error) {
	return s.getTenant(ctx, q)
}

type stubKeyStore struct {
	store.Key

	getParentKeys func(ctx context.Context, query store.GetParentKeysQuery) (store.GetParentKeysResult, error)
	getKeyByID    func(ctx context.Context, id, tenantID string) (*model.Key, error)
}

func (s *stubKeyStore) GetParentKeys(ctx context.Context, query store.GetParentKeysQuery) (store.GetParentKeysResult, error) {
	return s.getParentKeys(ctx, query)
}

func (s *stubKeyStore) GetKeyByID(ctx context.Context, id, tenantID string) (*model.Key, error) {
	return s.getKeyByID(ctx, id, tenantID)
}

func testHierarchy() spec.KeyHierarchy {
	return spec.KeyHierarchy{
		Name: "test-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot},
			{Kind: "K1", Role: spec.KeyRoleKek},
			{Kind: "K2", Role: spec.KeyRoleDek},
		},
	}
}

func testTopology() spec.Topology {
	return spec.Topology{
		Segments: []spec.TopologySegment{
			{Name: "agent-derived", Segment: spec.HierarchySegment{StartKind: "K1", EndKind: "K2"}},
		},
	}
}

var testRootSegment = spec.HierarchySegment{StartKind: "K0", EndKind: "K0"}

func tenantFound() store.Tenant {
	return &stubTenantStore{
		getTenant: func(_ context.Context, _ store.GetTenantQuery) (store.GetTenantResult, error) {
			return store.GetTenantResult{Tenant: model.Tenant{ID: validUUID}}, nil
		},
	}
}

func tenantReturning(err error) store.Tenant {
	return &stubTenantStore{
		getTenant: func(_ context.Context, _ store.GetTenantQuery) (store.GetTenantResult, error) {
			return store.GetTenantResult{}, err
		},
	}
}

func keyStoreReturning(key *model.Key, err error) store.Key {
	return &stubKeyStore{
		getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
			return key, err
		},
	}
}

func TestValidator_ValidateKeyAnnounce(t *testing.T) {
	storeErr := errors.New("boom")

	activeRootParent := &model.Key{
		ID:             "parent-id",
		TenantID:       validUUID,
		Kind:           "K0",
		LifeCycleState: model.KeyLifeCycleActive,
	}
	suspendedRootParent := &model.Key{
		ID:             "parent-id",
		TenantID:       validUUID,
		Kind:           "K0",
		LifeCycleState: model.KeyLifeCycleSuspended,
	}
	activeUnknownKindParent := &model.Key{
		ID:             "parent-id",
		TenantID:       validUUID,
		Kind:           "UNKNOWN",
		LifeCycleState: model.KeyLifeCycleActive,
	}

	tests := []struct {
		name     string
		input    validator.AnnounceInput
		tenants  store.Tenant
		keys     store.Key
		wantErr  error
		wantCode codes.Code
	}{
		{
			name:     "empty tenantID",
			input:    validator.AnnounceInput{TenantID: "", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrEmptyTenantID,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "empty keyKind",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrEmptyKeyKind,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "empty name",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrEmptyName,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "tenant not found",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantReturning(store.ErrTenantNotFound),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrInvalidTenantID,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "tenant store internal error",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantReturning(storeErr),
			keys:     &stubKeyStore{},
			wantErr:  storeErr,
			wantCode: codes.Internal,
		},
		{
			name:     "key kind not in hierarchy",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "UNKNOWN", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrInvalidKeyKind,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "target not in topology",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "missing-agent", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrTargetNotInTopolgy,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "target does not manage key kind",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K0", Name: "k0", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrTargetDoesNotManageKeyKind,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "non-root key with empty parentID",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: ""},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrNonRootKey,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "root key with parentID is rejected",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K0", Name: "k0", TargetName: "", ParentID: "some-parent"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrRootKeyParent,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "parent key not found",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "missing-parent"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(nil, store.ErrKeyNotFound),
			wantErr:  validator.ErrInvalidParentKey,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "parent key store internal error",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(nil, storeErr),
			wantErr:  storeErr,
			wantCode: codes.Internal,
		},
		{
			name:     "parent key not active",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(suspendedRootParent, nil),
			wantErr:  validator.ErrParentInvalidState,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "parent key skips a hierarchy layer",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K2", Name: "k2", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(activeRootParent, nil),
			wantErr:  validator.ErrParentKeyAdjecency,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "parent key kind unknown to hierarchy",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(activeUnknownKindParent, nil),
			wantErr:  validator.ErrParentKeyAdjecency,
			wantCode: codes.InvalidArgument,
		},
		{
			name:    "valid non-root key with active adjacent parent",
			input:   validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants: tenantFound(),
			keys:    keyStoreReturning(activeRootParent, nil),
			wantErr: nil,
		},
		{
			name:    "valid root key with empty parentID",
			input:   validator.AnnounceInput{TenantID: validUUID, KeyKind: "K0", Name: "k0", TargetName: "", ParentID: ""},
			tenants: tenantFound(),
			keys:    &stubKeyStore{},
			wantErr: nil,
		},
		{
			name:     "empty target does not manage non-root kind",
			input:    validator.AnnounceInput{TenantID: validUUID, KeyKind: "K1", Name: "k1", TargetName: "", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrTargetDoesNotManageKeyKind,
			wantCode: codes.FailedPrecondition,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := validator.NewValidator(testRootSegment, testTopology(), testHierarchy(), tc.tenants, tc.keys)

			ve := v.ValidateKeyAnnounce(t.Context(), tc.input)

			if tc.wantErr == nil {
				assert.Nil(t, ve)
				return
			}

			if assert.NotNil(t, ve) {
				assert.EqualError(t, ve, tc.wantErr.Error())
				assert.Equal(t, tc.wantCode, ve.ToProtoErrCode())
			}
		})
	}
}

func TestValidator_ValidateActivateRequest(t *testing.T) {
	tests := []struct {
		name    string
		input   validator.ActivateInput
		wantErr error
	}{
		{
			name:    "invalid tenantID",
			input:   validator.ActivateInput{TenantID: invalidUUID, KeyID: validUUID},
			wantErr: validator.ErrEmptyTenantID,
		},
		{
			name:    "invalid keyID",
			input:   validator.ActivateInput{TenantID: validUUID, KeyID: invalidUUID},
			wantErr: validator.ErrInvalidKeyID,
		},
		{
			name:    "both valid",
			input:   validator.ActivateInput{TenantID: validUUID, KeyID: validUUID},
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateActivateRequest(tc.input)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestValidator_ValidateTenant(t *testing.T) {
	errBoom := errors.New("boom")

	tests := []struct {
		name         string
		tenants      store.Tenant
		wantNil      bool
		wantErrIs    []error
		wantErrIsNot []error
	}{
		{
			name:    "tenant found",
			tenants: tenantFound(),
			wantNil: true,
		},
		{
			name:      "tenant not found",
			tenants:   tenantReturning(store.ErrTenantNotFound),
			wantErrIs: []error{store.ErrTenantNotFound},
		},
		{
			name:         "generic store error",
			tenants:      tenantReturning(errBoom),
			wantErrIs:    []error{errBoom},
			wantErrIsNot: []error{store.ErrTenantNotFound},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			step := validator.ValidateTenant(validUUID)
			err := step(t.Context(), store.Stores{Tenants: tc.tenants, Keys: &stubKeyStore{}})

			if tc.wantNil {
				assert.NoError(t, err)
				return
			}
			if !assert.Error(t, err) {
				return
			}
			for _, s := range tc.wantErrIs {
				assert.ErrorIs(t, err, s)
			}
			for _, s := range tc.wantErrIsNot {
				assert.NotErrorIs(t, err, s, "unexpected: err matches %v", s)
			}
		})
	}
}

func TestValidator_ValidateTransition(t *testing.T) {
	errBoom := errors.New("boom")

	tests := []struct {
		name         string
		key          *model.Key
		getKeyErr    error
		wantNil      bool
		wantErrIs    []error
		wantErrIsNot []error
	}{
		{
			name:      "key not found",
			getKeyErr: store.ErrKeyNotFound,
			wantErrIs: []error{store.ErrKeyNotFound},
		},
		{
			name:         "generic store error",
			getKeyErr:    errBoom,
			wantErrIs:    []error{errBoom},
			wantErrIsNot: []error{store.ErrKeyNotFound},
		},
		{
			name: "key still processing",
			key: &model.Key{
				ID:                 validUUID,
				LifeCycleState:     model.KeyLifeCyclePreActivation,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingInProgress},
			},
			wantErrIs: []error{validator.ErrKeyTransientState},
		},
		{
			name: "invalid transition",
			key: &model.Key{
				ID:                 validUUID,
				LifeCycleState:     model.KeyLifeCycleDestroyed,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
			},
			wantErrIs: []error{keylifecycle.ErrInvalidKeyStateTransition},
		},
		{
			name: "valid transition",
			key: &model.Key{
				ID:                 validUUID,
				LifeCycleState:     model.KeyLifeCyclePreActivation,
				KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
			},
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := keyStoreReturning(tc.key, tc.getKeyErr)
			step := validator.ValidateTransition(validUUID, validUUID, model.KeyLifeCycleActive)
			err := step(t.Context(), store.Stores{Tenants: tenantFound(), Keys: keys})

			if tc.wantNil {
				assert.NoError(t, err)
				return
			}
			if !assert.Error(t, err) {
				return
			}
			for _, s := range tc.wantErrIs {
				assert.ErrorIs(t, err, s)
			}
			for _, s := range tc.wantErrIsNot {
				assert.NotErrorIs(t, err, s, "unexpected: err matches %v", s)
			}
		})
	}
}

func TestValidator_ValidateKeyParents(t *testing.T) {
	errBoom := errors.New("boom")

	target := model.Key{
		ID:                 validUUID,
		Kind:               "K1",
		LifeCycleState:     model.KeyLifeCyclePreActivation,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
		ParentID:           new("parent-id"),
	}
	activeCompletedAncestor := model.Key{
		ID:                 "ancestor-id",
		Kind:               "K0",
		LifeCycleState:     model.KeyLifeCycleActive,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
	}
	suspendedAncestor := model.Key{
		ID:                 "ancestor-id",
		Kind:               "K0",
		LifeCycleState:     model.KeyLifeCycleSuspended,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted},
	}
	pendingAncestor := model.Key{
		ID:                 "ancestor-id",
		Kind:               "K0",
		LifeCycleState:     model.KeyLifeCycleActive,
		KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending},
	}

	tests := []struct {
		name      string
		parents   []model.Key
		listErr   error
		wantNil   bool
		wantErrIs []error
	}{
		{
			name:      "key not found",
			listErr:   store.ErrKeyNotFound,
			wantErrIs: []error{store.ErrKeyNotFound},
		},
		{
			name:      "generic store error",
			listErr:   errBoom,
			wantErrIs: []error{errBoom},
		},
		{
			name:      "strict ancestor not active",
			parents:   []model.Key{suspendedAncestor, target},
			wantErrIs: []error{validator.ErrParentKeyTransientState},
		},
		{
			name:      "strict ancestor not completed",
			parents:   []model.Key{pendingAncestor, target},
			wantErrIs: []error{validator.ErrParentKeyTransientState},
		},
		{
			name:    "only target key (root)",
			parents: []model.Key{target},
			wantNil: true,
		},
		{
			name:    "valid chain",
			parents: []model.Key{activeCompletedAncestor, target},
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := &stubKeyStore{
				getParentKeys: func(_ context.Context, _ store.GetParentKeysQuery) (store.GetParentKeysResult, error) {
					if tc.listErr != nil {
						return store.GetParentKeysResult{}, tc.listErr
					}
					return store.GetParentKeysResult{Keys: tc.parents}, nil
				},
			}
			step := validator.ValidateKeyParents(validUUID, validUUID)
			err := step(t.Context(), store.Stores{Tenants: tenantFound(), Keys: keys})

			if tc.wantNil {
				assert.NoError(t, err)
				return
			}
			if !assert.Error(t, err) {
				return
			}
			for _, s := range tc.wantErrIs {
				assert.ErrorIs(t, err, s)
			}
		})
	}
}
