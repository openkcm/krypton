package keyoperator_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// stubKeyVersionStore embeds store.KeyVersion so tests only need to
// implement the methods they exercise.
type stubKeyVersionStore struct {
	store.KeyVersion

	listKeyVersions        func(ctx context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error)
	createKeyVersion       func(ctx context.Context, q store.CreateKeyVersionQuery) (store.CreateKeyVersionResult, error)
	updateKeyVersionStates func(ctx context.Context, q store.UpdateKeyVersionStatesQuery) error
}

func (s *stubKeyVersionStore) ListKeyVersions(ctx context.Context, q store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
	return s.listKeyVersions(ctx, q)
}

func (s *stubKeyVersionStore) CreateKeyVersion(ctx context.Context, q store.CreateKeyVersionQuery) (store.CreateKeyVersionResult, error) {
	return s.createKeyVersion(ctx, q)
}

func (s *stubKeyVersionStore) UpdateKeyVersionStates(ctx context.Context, q store.UpdateKeyVersionStatesQuery) error {
	return s.updateKeyVersionStates(ctx, q)
}

// validKV returns a syntactically valid model.KeyVersion.
func validKV() model.KeyVersion {
	return model.KeyVersion{
		TenantID: testTenantID,
		KeyID:    testKeyID,
		Version:  1,
		Revision: 1,
	}
}

func staticResolver(kv model.KeyVersion, err error) keyoperator.KeyVersionResolver {
	return func(_ context.Context, _ store.Stores) (model.KeyVersion, error) {
		return kv, err
	}
}

func TestCreateKeyVersion(t *testing.T) {
	errBoom := errors.New("boom")

	tests := []struct {
		name         string
		resolveKV    model.KeyVersion
		resolveErr   error
		createErr    error
		wantErrIs    []error
		wantErrIsNot []error
		wantNil      bool
	}{
		{
			name:      "success",
			resolveKV: validKV(),
			wantNil:   true,
		},
		{
			name:         "resolver fails",
			resolveErr:   errBoom,
			wantErrIs:    []error{errBoom},
			wantErrIsNot: []error{keyoperator.ErrCreateKeyVersion},
		},
		{
			name:      "create fails",
			resolveKV: validKV(),
			createErr: errBoom,
			wantErrIs: []error{keyoperator.ErrCreateKeyVersion, errBoom},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kvStore := &stubKeyVersionStore{
				createKeyVersion: func(_ context.Context, _ store.CreateKeyVersionQuery) (store.CreateKeyVersionResult, error) {
					return store.CreateKeyVersionResult{}, tc.createErr
				},
			}
			step := keyoperator.CreateKeyVersion(testTenantID, testKeyID, staticResolver(tc.resolveKV, tc.resolveErr))
			err := step(t.Context(), store.Stores{KeyVersions: kvStore})

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

func TestUpdateKeyVersionState(t *testing.T) {
	errBoom := errors.New("boom")

	tests := []struct {
		name         string
		resolveKV    model.KeyVersion
		resolveErr   error
		updateErr    error
		wantErrIs    []error
		wantErrIsNot []error
		wantNil      bool
	}{
		{
			name:      "success",
			resolveKV: validKV(),
			wantNil:   true,
		},
		{
			name:         "resolver fails",
			resolveErr:   errBoom,
			wantErrIs:    []error{errBoom},
			wantErrIsNot: []error{keyoperator.ErrKeyVersionTransitionRejected, keyoperator.ErrUpdateKeyVersionState},
		},
		{
			name:         "CAS mismatch",
			resolveKV:    validKV(),
			updateErr:    store.ErrKeyVersionNotFound,
			wantErrIs:    []error{keyoperator.ErrKeyVersionTransitionRejected, store.ErrKeyVersionNotFound},
			wantErrIsNot: []error{keyoperator.ErrUpdateKeyVersionState},
		},
		{
			name:         "generic store error",
			resolveKV:    validKV(),
			updateErr:    errBoom,
			wantErrIs:    []error{keyoperator.ErrUpdateKeyVersionState, errBoom},
			wantErrIsNot: []error{keyoperator.ErrKeyVersionTransitionRejected},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kvStore := &stubKeyVersionStore{
				updateKeyVersionStates: func(_ context.Context, _ store.UpdateKeyVersionStatesQuery) error {
					return tc.updateErr
				},
			}
			step := keyoperator.UpdateKeyVersionState(
				testTenantID, testKeyID,
				staticResolver(tc.resolveKV, tc.resolveErr),
				keyoperator.VersionTransition{
					FromProcessing: []model.KeyVersionProcessingState{model.KeyVersionActivating},
					ToProcessing:   model.KeyVersionUsable,
					FromLifeCycle:  []model.KeyLifeCycleState{model.KeyLifeCyclePreActivation},
					ToLifeCycle:    model.KeyLifeCycleActive,
				},
			)
			err := step(t.Context(), store.Stores{KeyVersions: kvStore})

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

func TestGenerateAndSealKeyMaterial(t *testing.T) {
	t.Skip("integration test only")
}

func TestInitKeyVersion(t *testing.T) {
	errBoom := errors.New("boom")
	parentID := "parent-1"

	rootKey := &model.Key{ID: testKeyID, TenantID: testTenantID, Kind: "K0"}
	nonRootKey := &model.Key{ID: testKeyID, TenantID: testTenantID, Kind: "K1", ParentID: &parentID}

	parentUsable := model.KeyVersion{
		TenantID: testTenantID,
		KeyID:    parentID,
		Version:  3,
		Revision: 1,
	}

	t.Run("root key", func(t *testing.T) {
		keys := &stubKeyStore{
			getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
				return rootKey, nil
			},
		}
		resolve := keyoperator.InitKeyVersion(testTenantID, testKeyID)
		kv, err := resolve(t.Context(), store.Stores{Keys: keys})

		assert.NoError(t, err)
		assert.Equal(t, 1, kv.Version)
		assert.Equal(t, 1, kv.Revision)
		assert.Nil(t, kv.ParentKeyID)
		assert.Nil(t, kv.ParentKeyVersion)
		assert.Equal(t, model.KeyLifeCyclePreActivation, kv.LifeCycleState)
		assert.Equal(t, model.KeyVersionActivating, kv.ProcessingState)
	})

	t.Run("non-root with usable parent version", func(t *testing.T) {
		keys := &stubKeyStore{
			getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
				return nonRootKey, nil
			},
		}
		kvStore := &stubKeyVersionStore{
			listKeyVersions: func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
				return store.ListKeyVersionsResult{KeyVersions: []model.KeyVersion{parentUsable}}, nil
			},
		}
		resolve := keyoperator.InitKeyVersion(testTenantID, testKeyID)
		kv, err := resolve(t.Context(), store.Stores{Keys: keys, KeyVersions: kvStore})

		assert.NoError(t, err)
		assert.Equal(t, 1, kv.Version)
		assert.Equal(t, 1, kv.Revision)
		if assert.NotNil(t, kv.ParentKeyID) {
			assert.Equal(t, parentID, *kv.ParentKeyID)
		}
		if assert.NotNil(t, kv.ParentKeyVersion) {
			assert.Equal(t, 3, *kv.ParentKeyVersion)
		}
	})

	t.Run("GetKeyByID fails", func(t *testing.T) {
		keys := &stubKeyStore{
			getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
				return nil, errBoom
			},
		}
		resolve := keyoperator.InitKeyVersion(testTenantID, testKeyID)
		_, err := resolve(t.Context(), store.Stores{Keys: keys})

		assert.ErrorIs(t, err, keyoperator.ErrGetKey)
		assert.ErrorIs(t, err, errBoom)
	})

	t.Run("ListKeyVersions fails", func(t *testing.T) {
		keys := &stubKeyStore{
			getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
				return nonRootKey, nil
			},
		}
		kvStore := &stubKeyVersionStore{
			listKeyVersions: func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
				return store.ListKeyVersionsResult{}, errBoom
			},
		}
		resolve := keyoperator.InitKeyVersion(testTenantID, testKeyID)
		_, err := resolve(t.Context(), store.Stores{Keys: keys, KeyVersions: kvStore})

		assert.ErrorIs(t, err, keyoperator.ErrGetParentKeyVersion)
		assert.ErrorIs(t, err, errBoom)
	})

	t.Run("parent has no usable version", func(t *testing.T) {
		keys := &stubKeyStore{
			getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
				return nonRootKey, nil
			},
		}
		kvStore := &stubKeyVersionStore{
			listKeyVersions: func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
				return store.ListKeyVersionsResult{}, nil
			},
		}
		resolve := keyoperator.InitKeyVersion(testTenantID, testKeyID)
		_, err := resolve(t.Context(), store.Stores{Keys: keys, KeyVersions: kvStore})

		assert.ErrorIs(t, err, keyoperator.ErrParentNoUsableVersion)
	})

	t.Run("memoizes across calls", func(t *testing.T) {
		var getKeyCalls, listCalls int
		firstKey := &model.Key{ID: testKeyID, TenantID: testTenantID, Kind: "K1", ParentID: &parentID}
		secondKey := &model.Key{ID: "different-id", TenantID: testTenantID, Kind: "K1", ParentID: &parentID}

		keys := &stubKeyStore{
			getKeyByID: func(_ context.Context, _, _ string) (*model.Key, error) {
				getKeyCalls++
				if getKeyCalls == 1 {
					return firstKey, nil
				}
				return secondKey, nil
			},
		}
		kvStore := &stubKeyVersionStore{
			listKeyVersions: func(_ context.Context, _ store.ListKeyVersionsQuery) (store.ListKeyVersionsResult, error) {
				listCalls++
				return store.ListKeyVersionsResult{KeyVersions: []model.KeyVersion{parentUsable}}, nil
			},
		}

		resolve := keyoperator.InitKeyVersion(testTenantID, testKeyID)
		stores := store.Stores{Keys: keys, KeyVersions: kvStore}

		kv1, err1 := resolve(t.Context(), stores)
		kv2, err2 := resolve(t.Context(), stores)

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.Equal(t, kv1, kv2, "resolver should return the same key version on subsequent calls")
		assert.Equal(t, 1, getKeyCalls, "GetKeyByID should be called once")
		assert.Equal(t, 1, listCalls, "ListKeyVersions should be called once")
	})
}
