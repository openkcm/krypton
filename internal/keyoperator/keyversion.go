package keyoperator

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// VersionTransition holds the state transition inputs for
// UpdateKeyVersionState.
type VersionTransition struct {
	FromProcessing []model.KeyVersionProcessingState
	ToProcessing   model.KeyVersionProcessingState
	FromLifeCycle  []model.KeyLifeCycleState
	ToLifeCycle    model.KeyLifeCycleState
}

// KeyVersionResolver produces the key version a chain of steps operates
// on.
type KeyVersionResolver func(ctx context.Context, stores store.Stores) (model.KeyVersion, error)

// Class sentinels raised by key-version-level operations.
var (
	// ErrCreateKeyVersion signals a failed key version creation.
	ErrCreateKeyVersion = errors.New("failed to create key version")

	// ErrKeyVersionTransitionRejected signals that the compare-and-set
	// update did not match: the key version's current state does not
	// match the expected states.
	ErrKeyVersionTransitionRejected = errors.New("cannot transition key version: current state does not match the expected states")

	// ErrUpdateKeyVersionState signals a failed key version state update.
	ErrUpdateKeyVersionState = errors.New("failed to update key version life cycle and processing state")

	// ErrGenerateAndSealKeyMaterial signals a failed vault seal.
	ErrGenerateAndSealKeyMaterial = errors.New("failed to generate and seal key material")

	// ErrGetParentKeyVersion signals a failed read of the parent's key versions.
	ErrGetParentKeyVersion = errors.New("failed to get parent key version")

	// ErrParentNoUsableVersion signals the parent key has no usable version to link to.
	ErrParentNoUsableVersion = errors.New("parent key has no usable version")
)

// InitKeyVersion returns a memoized resolver for the first key version
// (v=1, r=1) of the target key. For non-root keys it resolves the
// parent's latest usable version. The returned value is preconfigured
// with LifeCyclePreActivation and ProcessingActivating.
func InitKeyVersion(tenantID, keyID string) KeyVersionResolver {
	var (
		once sync.Once
		kv   model.KeyVersion
		err  error
	)
	return func(ctx context.Context, stores store.Stores) (model.KeyVersion, error) {
		once.Do(func() {
			var key *model.Key
			key, err = stores.Keys.GetKeyByID(ctx, keyID, tenantID)
			if err != nil {
				err = fmt.Errorf("%w: %w", ErrGetKey, err)
				return
			}

			var parentKeyVersion *int
			if key.ParentID != nil {
				var pkv store.ListKeyVersionsResult
				pkv, err = stores.KeyVersions.ListKeyVersions(ctx, store.ListKeyVersionsQuery{
					TenantID:        key.TenantID,
					KeyID:           *key.ParentID,
					ProcessingState: model.KeyVersionUsable,
					LifeCycleState:  model.KeyLifeCycleActive,
					OrderBy: []store.KeyVersionOrder{
						store.KeyVersionOrderVersionDesc,
						store.KeyVersionOrderRevisionDesc,
					},
					Limit: 1,
				})
				if err != nil {
					err = fmt.Errorf("%w: %w", ErrGetParentKeyVersion, err)
					return
				}
				if len(pkv.KeyVersions) == 0 {
					err = ErrParentNoUsableVersion
					return
				}
				parentKeyVersion = new(pkv.KeyVersions[0].Version)
			}

			kv = model.NewKeyVersion(key.TenantID, key.ID, 1, key.ParentID, parentKeyVersion)
			kv.LifeCycleState = model.KeyLifeCyclePreActivation
			kv.ProcessingState = model.KeyVersionActivating
		})
		return kv, err
	}
}

// CreateKeyVersion returns a transaction step that persists the resolved
// key version.
func CreateKeyVersion(tenantID, keyID string, resolve KeyVersionResolver) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		kv, err := resolve(ctx, stores)
		if err != nil {
			return err
		}
		if _, err := stores.KeyVersions.CreateKeyVersion(ctx, store.CreateKeyVersionQuery{
			KeyVersion: kv,
		}); err != nil {
			return fmt.Errorf("%w: %w", ErrCreateKeyVersion, err)
		}
		return nil
	}
}

// UpdateKeyVersionState returns a transaction step that transitions the
// resolved key version's processing and life cycle states.
func UpdateKeyVersionState(tenantID, keyID string, resolve KeyVersionResolver, transition VersionTransition) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		kv, err := resolve(ctx, stores)
		if err != nil {
			return err
		}
		err = stores.KeyVersions.UpdateKeyVersionStates(ctx, store.UpdateKeyVersionStatesQuery{
			TenantID:            tenantID,
			KeyID:               keyID,
			Version:             kv.Version,
			Revision:            kv.Revision,
			FromProcessingState: transition.FromProcessing,
			ToProcessingState:   transition.ToProcessing,
			FromLifeCycleState:  transition.FromLifeCycle,
			ToLifeCycleState:    transition.ToLifeCycle,
		})
		if err != nil {
			if errors.Is(err, store.ErrKeyVersionNotFound) {
				return fmt.Errorf("%w: %w", ErrKeyVersionTransitionRejected, err)
			}
			return fmt.Errorf("%w: %w", ErrUpdateKeyVersionState, err)
		}
		return nil
	}
}

// GenerateAndSealKeyMaterial returns a transaction step that generates
// and seals the key material for the resolved key version. No-op for
// root keys. The vault write runs inside the transaction; a DB rollback
// after this point may orphan at most one unreferenced vault entry.
func GenerateAndSealKeyMaterial(manager *keyprocessor.Manager, tenantID, keyID string, resolve KeyVersionResolver) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		key, err := stores.Keys.GetKeyByID(ctx, keyID, tenantID)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrGetKey, err)
		}
		if key.ParentID == nil {
			return nil
		}

		kv, err := resolve(ctx, stores)
		if err != nil {
			return err
		}

		aad := fmt.Appendf(nil, "%s:%s:%d:%d:%d", key.TenantID, key.ID, kv.Version, kv.Revision, kv.CreatedAt)
		if _, err := manager.GenerateAndSealSecret(ctx, keyprocessor.GenerateAndSealSecretRequest{
			KeyVersion: kv,
			AAD:        aad,
			KeyKind:    key.Kind,
		}); err != nil {
			return fmt.Errorf("%w: %w", ErrGenerateAndSealKeyMaterial, err)
		}
		return nil
	}
}
