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

func TestValidator_ValidateKeyAnnounce(t *testing.T) {
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
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K0", Name: "k0", TargetName: "", ParentID: "some-parent"},
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
			input:   validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K0", Name: "k0", TargetName: "", ParentID: ""},
			tenants: tenantFound(),
			keys:    &stubKeyStore{},
			wantErr: nil,
		},
		{
			name:     "empty target does not manage non-root kind",
			input:    validator.AnnounceInput{TenantID: "tenant-1", KeyKind: "K1", Name: "k1", TargetName: "", ParentID: "parent-id"},
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

func TestValidator_ValidateKeyActivate(t *testing.T) {
	t.Run("validate input", func(t *testing.T) {
		// given
		tts := []struct {
			name     string
			input    validator.ActivateInput
			wantErr  error
			wantCode codes.Code
		}{
			{
				name:     "empty tenantID",
				input:    validator.ActivateInput{TenantID: "", KeyID: "key-id"},
				wantErr:  validator.ErrEmptyTenantID,
				wantCode: codes.InvalidArgument,
			},
			{
				name:     "empty keyID",
				input:    validator.ActivateInput{TenantID: "tenantID", KeyID: ""},
				wantErr:  validator.ErrInvalidKeyID,
				wantCode: codes.InvalidArgument,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				v := validator.NewValidator(testRootSegment, testTopology(), testHierarchy(), &stubTenantStore{}, &stubKeyStore{})

				// when
				ve := v.ValidateKeyActivate(t.Context(), tt.input)

				// then
				assert.NotNil(t, ve)
				assert.EqualError(t, ve, tt.wantErr.Error())
				assert.Equal(t, tt.wantCode, ve.ToProtoErrCode())
			})
		}
	})
	t.Run("should return error if tenant not found", func(t *testing.T) {
		// given
		v := validator.NewValidator(testRootSegment, testTopology(), testHierarchy(), tenantReturning(store.ErrTenantNotFound), &stubKeyStore{})

		// when
		ve := v.ValidateKeyActivate(t.Context(), validator.ActivateInput{TenantID: "tenant-1", KeyID: "key-id"})

		// then
		assert.NotNil(t, ve)
		assert.EqualError(t, ve, validator.ErrInvalidTenantID.Error())
		assert.Equal(t, codes.FailedPrecondition, ve.ToProtoErrCode())
	})

	t.Run("should return error if tenant store internal error", func(t *testing.T) {
		// given
		v := validator.NewValidator(testRootSegment, testTopology(), testHierarchy(), tenantReturning(assert.AnError), &stubKeyStore{})

		// when
		ve := v.ValidateKeyActivate(t.Context(), validator.ActivateInput{TenantID: "tenant-1", KeyID: "key-id"})

		// then
		assert.NotNil(t, ve)
		assert.EqualError(t, ve, validator.ErrFailedToGetTenant.Error())
		assert.Equal(t, codes.Internal, ve.ToProtoErrCode())
	})

	t.Run("should return error if getparents returns an error", func(t *testing.T) {
		// given
		stubKeys := &stubKeyStore{
			getParentKeys: func(_ context.Context, _ store.GetParentKeysQuery) (store.GetParentKeysResult, error) {
				return store.GetParentKeysResult{}, errors.New("boom")
			},
		}
		v := validator.NewValidator(testRootSegment, testTopology(), testHierarchy(), tenantFound(), stubKeys)

		// when
		ve := v.ValidateKeyActivate(t.Context(), validator.ActivateInput{TenantID: "tenant-1", KeyID: "key-id"})

		// then
		assert.NotNil(t, ve)
		assert.EqualError(t, ve, validator.ErrFailedToGetParentKeys.Error())
		assert.Equal(t, codes.Internal, ve.ToProtoErrCode())
	})

	t.Run("keys hierarchy validation", func(t *testing.T) {
		tts := []struct {
			name       string
			parentKeys []model.Key
			wantErr    error
			wantCode   codes.Code
		}{
			{
				name:       "should return error if key has no parent keys",
				parentKeys: []model.Key{},
				wantErr:    validator.ErrFailedToGetParentKeys,
				wantCode:   codes.FailedPrecondition,
			},
			{
				name: "should return error if parent key is not active",
				parentKeys: []model.Key{
					{Kind: "K0", LifeCycleState: model.KeyLifeCycleDestroyed, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
					{Kind: "K1", LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}, ParentID: new("parent-id")},
				},
				wantErr:  validator.ErrParentKeyTransientState,
				wantCode: codes.FailedPrecondition,
			},
			{
				name: "should return error if parent key is not completed",
				parentKeys: []model.Key{
					{Kind: "K0", LifeCycleState: model.KeyLifeCycleActive, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingPending}},
					{Kind: "K1", LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}, ParentID: new("parent-id")},
				},
				wantErr:  validator.ErrParentKeyTransientState,
				wantCode: codes.FailedPrecondition,
			},
			{
				name: "shoud return error if key to activate is not in completed state",
				parentKeys: []model.Key{
					{Kind: "K0", LifeCycleState: model.KeyLifeCycleActive, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
					{Kind: "K1", LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingInProgress}, ParentID: new("parent-id")},
				},
				wantErr:  validator.ErrKeyTransientState,
				wantCode: codes.FailedPrecondition,
			},
			{
				name: "should return error if key to activate is not in valid state transition",
				parentKeys: []model.Key{
					{Kind: "K0", LifeCycleState: model.KeyLifeCycleActive, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
					{Kind: "K1", LifeCycleState: model.KeyLifeCycleDestroyed, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}, ParentID: new("parent-id")},
				},
				wantErr:  errors.New("cannot transition from destroyed to active: invalid key state transition"),
				wantCode: codes.FailedPrecondition,
			},
			{
				name: "should return error if parent keys are not adjacent",
				parentKeys: []model.Key{
					{Kind: "K0", LifeCycleState: model.KeyLifeCycleActive, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
					{Kind: "K2", LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
				},
				wantErr:  validator.ErrParentKeyNotInOrder,
				wantCode: codes.FailedPrecondition,
			},
			{
				name: "should return nil if all parent keys are active and adjacent",
				parentKeys: []model.Key{
					{Kind: "K0", LifeCycleState: model.KeyLifeCycleActive, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}},
					{Kind: "K1", LifeCycleState: model.KeyLifeCyclePreActivation, KeyProcessingState: model.KeyProcessingState{Status: model.KeyProcessingCompleted}, ParentID: new("parent-id")},
				},
				wantErr: nil,
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				stubKeys := &stubKeyStore{
					getParentKeys: func(_ context.Context, _ store.GetParentKeysQuery) (store.GetParentKeysResult, error) {
						return store.GetParentKeysResult{Keys: tt.parentKeys}, nil
					},
				}

				v := validator.NewValidator(testRootSegment, testTopology(), testHierarchy(), tenantFound(), stubKeys)
				// when
				ve := v.ValidateKeyActivate(t.Context(), validator.ActivateInput{TenantID: "tenant-1", KeyID: "key-id"})

				// then
				if tt.wantErr == nil {
					assert.Nil(t, ve)
					return
				}
				assert.NotNil(t, ve)
				assert.EqualError(t, ve, tt.wantErr.Error())
				assert.Equal(t, tt.wantCode, ve.ToProtoErrCode())
			})
		}
	})
}
