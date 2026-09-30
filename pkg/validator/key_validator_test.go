package validator_test

import (
	"context"
	"errors"
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

var (
	validUUID   = uuid.New().String()
	invalidUUID = "invalid-uuid"
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

func TestValidator_ValidateKeyUpsert(t *testing.T) {
	baseValid := validator.UpsertKeyInput{
		TenantID:       validUUID,
		KeyID:          uuid.New().String(),
		Kind:           "K1",
		Name:           "some-name",
		ManagedBy:      "agent-aws",
		ParentID:       uuid.New().String(),
		LifecycleState: string(model.KeyLifeCyclePreActivation),
	}

	withField := func(mut func(*validator.UpsertKeyInput)) validator.UpsertKeyInput {
		in := baseValid
		mut(&in)
		return in
	}

	tests := []struct {
		name    string
		input   validator.UpsertKeyInput
		wantErr error
	}{
		{
			name:    "invalid tenantID",
			input:   withField(func(in *validator.UpsertKeyInput) { in.TenantID = invalidUUID }),
			wantErr: validator.ErrInvalidTenantID,
		},
		{
			name:    "invalid keyID",
			input:   withField(func(in *validator.UpsertKeyInput) { in.KeyID = invalidUUID }),
			wantErr: validator.ErrInvalidKeyID,
		},
		{
			name:    "empty kind",
			input:   withField(func(in *validator.UpsertKeyInput) { in.Kind = "" }),
			wantErr: validator.ErrEmptyKeyKind,
		},
		{
			name:    "empty name",
			input:   withField(func(in *validator.UpsertKeyInput) { in.Name = "" }),
			wantErr: validator.ErrEmptyName,
		},
		{
			name:    "empty managed_by",
			input:   withField(func(in *validator.UpsertKeyInput) { in.ManagedBy = "" }),
			wantErr: validator.ErrEmptyManagedBy,
		},
		{
			name:    "invalid parent_id",
			input:   withField(func(in *validator.UpsertKeyInput) { in.ParentID = invalidUUID }),
			wantErr: validator.ErrInvalidParentID,
		},
		{
			name:    "empty parent_id",
			input:   withField(func(in *validator.UpsertKeyInput) { in.ParentID = "" }),
			wantErr: validator.ErrInvalidParentID,
		},
		{
			name:    "empty lifecycle_state",
			input:   withField(func(in *validator.UpsertKeyInput) { in.LifecycleState = "" }),
			wantErr: validator.ErrEmptyLifecycleState,
		},
		{
			name:    "unknown lifecycle_state",
			input:   withField(func(in *validator.UpsertKeyInput) { in.LifecycleState = "bogus" }),
			wantErr: validator.ErrUnknownLifecycleState,
		},
		{
			name:    "valid with pre-activation",
			input:   baseValid,
			wantErr: nil,
		},
		{
			name:    "valid with active",
			input:   withField(func(in *validator.UpsertKeyInput) { in.LifecycleState = string(model.KeyLifeCycleActive) }),
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateKeyUpsert(tc.input)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
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

func TestValidator_ValidateKeyAnnounceRequest(t *testing.T) {
	cfg := config.RootConfig{
		Segment: spec.HierarchySegment{StartKind: "K0", EndKind: "K1"},
		Hierarchy: spec.KeyHierarchy{
			Name: "test-hierarchy",
			KeySpecs: []spec.KeySpec{
				{Kind: "K0", Role: spec.KeyRoleRoot},
				{Kind: "K1", Role: spec.KeyRoleKek},
				{Kind: "K2", Role: spec.KeyRoleDek},
			},
		},
		Topology: spec.Topology{
			Segments: []spec.TopologySegment{
				{
					Name:    "agent-aws",
					Segment: spec.HierarchySegment{StartKind: "K2", EndKind: "K2"},
				},
			},
		},
	}

	baseValid := validator.AnnounceInput{
		TenantID: validUUID,
		KeyKind:  "K0",
		Name:     "some-name",
	}

	withField := func(mut func(*validator.AnnounceInput)) validator.AnnounceInput {
		in := baseValid
		mut(&in)
		return in
	}

	tests := []struct {
		name    string
		input   validator.AnnounceInput
		wantErr error
	}{
		{
			name:    "invalid tenantID",
			input:   withField(func(in *validator.AnnounceInput) { in.TenantID = invalidUUID }),
			wantErr: validator.ErrInvalidTenantID,
		},
		{
			name:    "empty name",
			input:   withField(func(in *validator.AnnounceInput) { in.Name = "" }),
			wantErr: validator.ErrEmptyName,
		},
		{
			name:    "empty key kind",
			input:   withField(func(in *validator.AnnounceInput) { in.KeyKind = "" }),
			wantErr: validator.ErrEmptyKeyKind,
		},
		{
			name:    "target not in topology",
			input:   withField(func(in *validator.AnnounceInput) { in.TargetName = "unknown" }),
			wantErr: validator.ErrTargetNotInTopology,
		},
		{
			name: "target does not manage key kind",
			input: withField(func(in *validator.AnnounceInput) {
				in.TargetName = "agent-aws"
				in.KeyKind = "K0"
			}),
			wantErr: validator.ErrTargetDoesNotManageKeyKind,
		},
		{
			name:    "key kind outside default segment",
			input:   withField(func(in *validator.AnnounceInput) { in.KeyKind = "K2" }),
			wantErr: validator.ErrTargetDoesNotManageKeyKind,
		},
		{
			name:    "valid in default segment",
			input:   baseValid,
			wantErr: nil,
		},
		{
			name: "valid via target",
			input: withField(func(in *validator.AnnounceInput) {
				in.TargetName = "agent-aws"
				in.KeyKind = "K2"
			}),
			wantErr: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validator.ValidateKeyAnnounceRequest(tc.input, cfg)
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestValidator_ValidateKeyHierarchy(t *testing.T) {
	errBoom := errors.New("boom")

	hierarchy := spec.KeyHierarchy{
		Name: "test-hierarchy",
		KeySpecs: []spec.KeySpec{
			{Kind: "K0", Role: spec.KeyRoleRoot},
			{Kind: "K1", Role: spec.KeyRoleKek},
			{Kind: "K2", Role: spec.KeyRoleDek},
		},
	}

	tests := []struct {
		name      string
		key       model.Key
		parent    *model.Key
		getKeyErr error
		wantNil   bool
		wantErrIs []error
	}{
		{
			name:      "unknown key kind",
			key:       model.Key{TenantID: validUUID, Kind: "ZZ"},
			wantErrIs: []error{validator.ErrInvalidKeyKind},
		},
		{
			name:    "root without parent",
			key:     model.Key{TenantID: validUUID, Kind: "K0"},
			wantNil: true,
		},
		{
			name:      "root with parent",
			key:       model.Key{TenantID: validUUID, Kind: "K0", ParentID: new("parent-id")},
			wantErrIs: []error{validator.ErrRootKeyParent},
		},
		{
			name:      "non-root without parent",
			key:       model.Key{TenantID: validUUID, Kind: "K1"},
			wantErrIs: []error{validator.ErrNonRootKey},
		},
		{
			name:      "parent not found",
			key:       model.Key{TenantID: validUUID, Kind: "K1", ParentID: new("parent-id")},
			getKeyErr: store.ErrKeyNotFound,
			wantErrIs: []error{validator.ErrInvalidParentKey},
		},
		{
			name:      "generic store error",
			key:       model.Key{TenantID: validUUID, Kind: "K1", ParentID: new("parent-id")},
			getKeyErr: errBoom,
			wantErrIs: []error{errBoom},
		},
		{
			name:      "non-adjacent parent",
			key:       model.Key{TenantID: validUUID, Kind: "K2", ParentID: new("parent-id")},
			parent:    &model.Key{ID: "parent-id", Kind: "K0"},
			wantErrIs: []error{validator.ErrParentKeyAdjacency},
		},
		{
			name:    "valid adjacency",
			key:     model.Key{TenantID: validUUID, Kind: "K1", ParentID: new("parent-id")},
			parent:  &model.Key{ID: "parent-id", Kind: "K0"},
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys := keyStoreReturning(tc.parent, tc.getKeyErr)
			step := validator.ValidateKeyHierarchy(tc.key, hierarchy)
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
			name: "invalid transition",
			key: &model.Key{
				ID:             validUUID,
				LifeCycleState: model.KeyLifeCycleDestroyed,
			},
			wantErrIs: []error{keylifecycle.ErrInvalidKeyStateTransition},
		},
		{
			name: "valid transition",
			key: &model.Key{
				ID:             validUUID,
				LifeCycleState: model.KeyLifeCyclePreActivation,
			},
			wantNil: true,
		},
		{
			name: "no-op due to unchanged lifecycle state",
			key: &model.Key{
				ID:             validUUID,
				LifeCycleState: model.KeyLifeCycleActive,
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
