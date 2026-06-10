package validator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"

	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

type stubTenantStore struct {
	store.Tenant

	getTenant func(ctx context.Context, q store.GetTenantQuery) (store.GetTenantResult, error)
}

func (s *stubTenantStore) GetTenant(ctx context.Context, q store.GetTenantQuery) (store.GetTenantResult, error) {
	return s.getTenant(ctx, q)
}

type stubKeyStore struct {
	store.Key

	getKeyByID func(ctx context.Context, id, tenantID string) (*model.Key, error)
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
			{Name: "agent-root", Segment: spec.HierarchySegment{StartKind: "K0", EndKind: "K0"}},
			{Name: "agent-derived", Segment: spec.HierarchySegment{StartKind: "K1", EndKind: "K2"}},
		},
	}
}

func tenantFound() store.Tenant {
	return &stubTenantStore{
		getTenant: func(_ context.Context, _ store.GetTenantQuery) (store.GetTenantResult, error) {
			return store.GetTenantResult{Tenant: model.Tenant{ID: "tenant-1"}}, nil
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

func TestValidator_ValidateAnnounceKey(t *testing.T) {
	storeErr := errors.New("boom")

	activeRootParent := &model.Key{
		ID:             "parent-id",
		TenantID:       "tenant-1",
		Kind:           "K0",
		LifeCycleState: model.KeyLifeCycleActive,
	}
	suspendedRootParent := &model.Key{
		ID:             "parent-id",
		TenantID:       "tenant-1",
		Kind:           "K0",
		LifeCycleState: model.KeyLifeCycleSuspended,
	}
	activeUnknownKindParent := &model.Key{
		ID:             "parent-id",
		TenantID:       "tenant-1",
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
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrEmptyKeyKind,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "empty name",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrEmptyName,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "tenant not found",
			input:    validator.AnnounceInput{TenantID: "missing", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantReturning(store.ErrTenantNotFound),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrInvalidTenantID,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "tenant store internal error",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantReturning(storeErr),
			keys:     &stubKeyStore{},
			wantErr:  storeErr,
			wantCode: codes.Internal,
		},
		{
			name:     "key kind not in hierarchy",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "UNKNOWN", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrInvalidKeyKind,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "target not in topology",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "missing-agent", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrTargetNotInTopolgy,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "target does not manage key kind",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K0", Name: "k0", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrTargetDoesNotManageKeyKind,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "non-root key with empty parentID",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: ""},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrNonRootKey,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "root key with parentID is rejected",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K0", Name: "k0", TargetName: "agent-root", ParentID: "some-parent"},
			tenants:  tenantFound(),
			keys:     &stubKeyStore{},
			wantErr:  validator.ErrRootKeyParent,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "parent key not found",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "missing-parent"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(nil, store.ErrKeyNotFound),
			wantErr:  validator.ErrInvalidParentKey,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "parent key store internal error",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(nil, storeErr),
			wantErr:  storeErr,
			wantCode: codes.Internal,
		},
		{
			name:     "parent key not active",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(suspendedRootParent, nil),
			wantErr:  validator.ErrParentInvalidState,
			wantCode: codes.FailedPrecondition,
		},
		{
			name:     "parent key skips a hierarchy layer",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K2", Name: "k2", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(activeRootParent, nil),
			wantErr:  validator.ErrParentKeyAdjecency,
			wantCode: codes.InvalidArgument,
		},
		{
			name:     "parent key kind unknown to hierarchy",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants:  tenantFound(),
			keys:     keyStoreReturning(activeUnknownKindParent, nil),
			wantErr:  validator.ErrParentKeyAdjecency,
			wantCode: codes.InvalidArgument,
		},
		{
			name:    "valid non-root key with active adjacent parent",
			input:   validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "agent-derived", ParentID: "parent-id"},
			tenants: tenantFound(),
			keys:    keyStoreReturning(activeRootParent, nil),
			wantErr: nil,
		},
		{
			name:    "valid root key with empty parentID",
			input:   validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K0", Name: "k0", TargetName: "agent-root", ParentID: ""},
			tenants: tenantFound(),
			keys:    &stubKeyStore{},
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := validator.NewValidator(testTopology(), testHierarchy(), tc.tenants, tc.keys)

			ve := v.ValidateAnnounceKey(t.Context(), tc.input)

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
