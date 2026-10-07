// Package keyoperator provides transaction-scoped operations for keys and
// key versions. Each constructor returns a store.TransactionFunc that can
// be composed into a store.ChainTransaction.
package keyoperator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/internal/handler"
	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type JobGroupPreparer interface {
	PrepareJobGroup(ctx context.Context, group orbital.JobGroup) (orbital.JobGroup, error)
}

// Transition holds the state transition inputs for UpdateKeyState.
type Transition struct {
	FromLifeCycle  []model.KeyLifeCycleState
	ToLifeCycle    model.KeyLifeCycleState
	FromProcessing []model.KeyProcessingStatus
	ToProcessing   model.KeyProcessingStatus
}

type (
	keySelectorFn func(key model.Key) bool
	KeySelector   struct {
		State  model.KeyLifeCycleState
		Status model.KeyProcessingStatus
	}
	ApplyKeyActionRequest struct {
		TenantID     string
		KeyID        string
		ToState      model.KeyLifeCycleState
		Selector     keySelectorFn
		Cascading    bool
		AllowPartial bool
		JobType      string
		JobGroupType string
	}
)

type keyExclusion struct {
	excluded        map[string]struct{}
	excludedInLayer int
	allowPartial    bool
}

// Class sentinels raised by key-level operations. The transport layer
// switches on these via errors.Is to map to gRPC status + proto detail
// codes.
var (
	// ErrKeyTransitionRejected signals that the compare-and-set update
	// did not match: the key's current state does not match the expected
	// states.
	ErrKeyTransitionRejected = errors.New("cannot transition key: current state does not match the expected states")

	// ErrUpdateKeyState signals a failed key state update.
	ErrUpdateKeyState = errors.New("failed to update key life cycle and processing state")

	// ErrGetKey signals a failed read of the target key.
	ErrGetKey = errors.New("failed to get key")

	// ErrCreateKey signals a failed key creation.
	ErrCreateKey = errors.New("failed to create key")

	// ErrKeyConflict signals that an existing key with the same identity
	// (tenant + id or tenant + name) does not match the upsert request:
	// one of Name, TenantID, ManagedBy, Kind, or ParentID differs.
	ErrKeyConflict = errors.New("existing key does not match upsert request")

	// ErrNilKey signals that the given key is nil
	ErrNilKey = errors.New("key must not be nil")

	// ErrNoKeysFound signals that no keys were found in the key tree.
	ErrNoKeysFound = errors.New("keys not found")

	// ErrInternal signals an internal error.
	ErrInternal = errors.New("internal error")
)

// UpsertKey inserts or reconciles newKey by (tenant, name), updating
// newKey in place with the persisted identity.
func UpsertKey(newKey *model.Key) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		if newKey == nil {
			return ErrNilKey
		}

		err := stores.Keys.CreateKey(ctx, *newKey)
		if err == nil {
			return nil
		}
		if !errors.Is(err, store.ErrKeyInsertConflict) {
			return fmt.Errorf("%w: %w", ErrCreateKey, err)
		}

		existing, err := stores.Keys.GetKeyByName(ctx, store.GetKeyByNameQuery{
			TenantID: newKey.TenantID,
			Name:     newKey.Name,
		})
		if errors.Is(err, store.ErrKeyNotFound) {
			existing, err = stores.Keys.GetKeyByID(ctx, newKey.ID, newKey.TenantID)
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrGetKey, err)
		}
		if !existing.IsSame(newKey) {
			return ErrKeyConflict
		}

		// conflict: adopt the existing row's identity.
		newKey.ID = existing.ID

		err = stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:         existing.ID,
			TenantID:   existing.TenantID,
			ToState:    newKey.LifeCycleState,
			ToStatus:   newKey.KeyProcessingState.Status,
			FromState:  []model.KeyLifeCycleState{existing.LifeCycleState},
			FromStatus: []model.KeyProcessingStatus{model.KeyProcessingPending, model.KeyProcessingFailed},
		})
		// compare-and-swap matched zero rows: row is already in the target state (idempotent replay).
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %w", ErrUpdateKeyState, err)
		}
		return nil
	}
}

// UpdateKeyState returns a transaction step that transitions the key's
// life cycle and processing status.
func UpdateKeyState(tenantID, keyID string, transition Transition) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		err := stores.Keys.UpdateKeyStates(ctx, store.UpdateKeyStatesQuery{
			ID:         keyID,
			TenantID:   tenantID,
			FromState:  transition.FromLifeCycle,
			ToState:    transition.ToLifeCycle,
			FromStatus: transition.FromProcessing,
			ToStatus:   transition.ToProcessing,
		})
		if err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				return fmt.Errorf("%w: %w", ErrKeyTransitionRejected, err)
			}
			return fmt.Errorf("%w: %w", ErrUpdateKeyState, err)
		}
		return nil
	}
}

func KeyWithKeySelector(selectors ...KeySelector) keySelectorFn {
	return func(key model.Key) bool {
		for _, selector := range selectors {
			if key.LifeCycleState == selector.State && key.KeyProcessingState.Status == selector.Status {
				return true
			}
		}
		return false
	}
}

// ApplyKeyAction traverses a key tree top-down and builds a job group for
// keys that need a lifecycle transition. Each key is checked in order:
// parent excluded → transition invalid → already completed → selector rejects.
// Completed keys are skipped (children remain reachable); all other failures
// exclude the key and its descendants. When AllowPartial is false, the first
// exclusion aborts the operation.
func ApplyKeyAction(ctx context.Context, stores store.Stores, preparer JobGroupPreparer, action ApplyKeyActionRequest) (orbital.JobGroup, error) {
	kt, err := fetchKeytree(ctx, stores.Keys, action)
	if err != nil {
		return orbital.JobGroup{}, err
	}

	exc := newKeyExclusion(action.AllowPartial)

	if action.Selector == nil {
		action.Selector = func(model.Key) bool { return true }
	}

	var jobs []orbital.Job

	for layer := range kt.IterKeysByLayerAsc() {
		ids := make([]handler.KeyIdentifier, 0, len(layer))

		exc.resetLayerCount()

		for _, key := range layer {
			// checking if the parent key is excluded, if so, exclude the child key as well
			if key.ParentID != nil {
				if exc.isExcluded(*key.ParentID) {
					err := exc.exclude(key.ID)
					if err != nil {
						return orbital.JobGroup{}, err
					}
					continue
				}
			}

			// excluding keys that cannot transition to the target state
			if key.LifeCycleState != action.ToState {
				if keylifecycle.ValidateTransition(key.LifeCycleState, action.ToState) != nil {
					err := exc.exclude(key.ID)
					if err != nil {
						return orbital.JobGroup{}, err
					}
					continue
				}
			}

			// skipping keys that are already in the target state and have completed processing
			if key.LifeCycleState == action.ToState && key.KeyProcessingState.Status == model.KeyProcessingCompleted {
				continue
			}

			// filtering keys that do not match the selector criteria
			if !action.Selector(key) {
				err := exc.exclude(key.ID)
				if err != nil {
					return orbital.JobGroup{}, err
				}
				continue
			}

			// updating the key state to the target state and setting processing status to in progress
			err := UpdateKeyState(key.TenantID, key.ID, Transition{
				FromLifeCycle:  []model.KeyLifeCycleState{key.LifeCycleState},
				ToLifeCycle:    action.ToState,
				FromProcessing: []model.KeyProcessingStatus{key.KeyProcessingState.Status},
				ToProcessing:   model.KeyProcessingPending,
			})(ctx, stores)
			if err != nil {
				return orbital.JobGroup{}, fmt.Errorf("updating key %s state: %w", key.ID, err)
			}

			ids = append(ids, handler.KeyIdentifier{
				ID:       key.ID,
				TenantID: key.TenantID,
			})
		}

		// If every key in this layer was excluded, all descendants will
		// cascade-exclude too — skip remaining layers.
		// (Only reachable when AllowPartial is true; otherwise exclude()
		// returns an error before the counter is incremented.)
		if exc.allExcluded(len(layer)) {
			break
		}

		if len(ids) == 0 {
			continue
		}

		data, err := json.Marshal(handler.KeyLayer{Identifiers: ids})
		if err != nil {
			return orbital.JobGroup{}, fmt.Errorf("%w: marshaling keys for job data: %w", ErrInternal, err)
		}

		jobs = append(jobs, orbital.NewJob(action.JobType, data))
	}

	if len(jobs) == 0 {
		return orbital.JobGroup{}, ErrNoKeysFound
	}

	return preparer.PrepareJobGroup(ctx, orbital.NewJobGroup(action.JobGroupType, jobs...))
}

func newKeyExclusion(allowPartial bool) *keyExclusion {
	return &keyExclusion{
		allowPartial: allowPartial,
		excluded:     make(map[string]struct{}),
	}
}

func (e *keyExclusion) exclude(id string) error {
	if !e.allowPartial {
		return fmt.Errorf("%w: some keys were excluded from the action due to state or selector mismatch", ErrNoKeysFound)
	}
	e.excluded[id] = struct{}{}
	e.excludedInLayer++
	return nil
}

func (e *keyExclusion) isExcluded(id string) bool {
	_, ok := e.excluded[id]
	return ok
}

// allExcluded reports whether every key in a layer of the given size was excluded.
func (e *keyExclusion) allExcluded(layerSize int) bool {
	return e.excludedInLayer == layerSize
}

func (e *keyExclusion) resetLayerCount() {
	e.excludedInLayer = 0
}

func fetchKeytree(ctx context.Context, keyStore store.Key, action ApplyKeyActionRequest) (model.KeyTreeTraverser, error) {
	// cascading is true, get all descendant keys and return the key tree
	if action.Cascading {
		kt, err := keyStore.GetDescendantKeys(ctx, store.GetDescendantKeysQuery{
			KeyID:    action.KeyID,
			TenantID: action.TenantID,
		})
		if err != nil {
			return nil, err
		}
		return kt.KeyTree, nil
	}

	// getting the key by ID and returning it as a single-layer key tree
	key, err := keyStore.GetKeyByID(ctx, action.KeyID, action.TenantID)
	if err != nil {
		return nil, err
	}
	return model.KeyTree{[]model.Key{*key}}, nil
}
