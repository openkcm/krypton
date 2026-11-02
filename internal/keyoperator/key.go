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

type KeyFilter struct {
	LifeCycleState model.KeyLifeCycleState
	Status         []model.KeyProcessingStatus
}

type ApplyKeyActionRequest struct {
	TenantID     string
	KeyID        string
	ToState      model.KeyLifeCycleState
	KeyFilters   []KeyFilter
	JobType      string
	JobGroupType string
	Cascading    bool
	// BottomUp, when true, iterates the key tree from leaves to root
	// (using IterKeysByLayerDsc) instead of the default root-to-leaf order.
	// Set to true when the action must reach leaves before their parents
	// (e.g. SuspendKey).
	BottomUp bool
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

	// ErrNoEligibleKeys signals that the key tree was non-empty but all
	// keys were already at the target state with completed processing;
	// no transition was required.
	ErrNoEligibleKeys = errors.New("no eligible keys found for processing")

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
			FromStatus: []model.KeyProcessingStatus{existing.KeyProcessingState.Status},
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

// ApplyKeyAction fetches a key tree (single key or full descendant tree
// depending on Cascading), then iterates layer by layer from root to leaf
// building a job group. Keys already at the target state with completed
// processing are skipped; all other keys are transitioned to
// (ToState, Pending) via a compare-and-set update. Each layer with at
// least one transitioned key produces one job. Returns ErrNoKeysFound
// when no keys require processing.
func ApplyKeyAction(ctx context.Context, stores store.Stores, preparer JobGroupPreparer, action ApplyKeyActionRequest) (orbital.JobGroup, error) {
	kt, err := fetchKeytree(ctx, stores.Keys, action)
	if err != nil {
		return orbital.JobGroup{}, err
	}

	var jobs []orbital.Job

	itr := kt.IterKeysByLayerAsc()
	if action.BottomUp {
		itr = kt.IterKeysByLayerDsc()
	}
	for layer := range itr {
		ids := make([]handler.KeyIdentifier, 0, len(layer))

		for _, key := range layer {
			// skipping keys that are already in the target state and have completed processing
			if key.LifeCycleState == action.ToState && key.KeyProcessingState.Status == model.KeyProcessingCompleted {
				continue
			}

			// updating the key state to the target state and setting processing status to pending
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
		return orbital.JobGroup{}, fmt.Errorf("%w: no actionable keys found", ErrNoEligibleKeys)
	}

	return preparer.PrepareJobGroup(ctx, orbital.NewJobGroup(action.JobGroupType, jobs...))
}

func fetchKeytree(ctx context.Context, keyStore store.Key, action ApplyKeyActionRequest) (model.KeyTreeTraverser, error) {
	// cascading is true, get all descendant keys and return the key tree
	if action.Cascading {
		filters := toStoreFilters(action.KeyFilters)
		kt, err := keyStore.GetDescendantKeys(ctx, store.GetDescendantKeysQuery{
			KeyID:    action.KeyID,
			TenantID: action.TenantID,
			Filters:  filters,
		})
		if err != nil {
			return nil, mapKeyNotFoundErr(err)
		}
		return kt.KeyTree, nil
	}

	// getting the key by ID and returning it as a single-layer key tree
	key, err := keyStore.GetKeyByID(ctx, action.KeyID, action.TenantID)
	if err != nil {
		return nil, mapKeyNotFoundErr(err)
	}
	for _, f := range action.KeyFilters {
		if f.LifeCycleState == key.LifeCycleState && (len(f.Status) == 0 || key.KeyProcessingState.Status.IsOneOf(f.Status...)) {
			return model.KeyTree{[]model.Key{*key}}, nil
		}
	}
	return nil, ErrNoKeysFound
}

func toStoreFilters(fs []KeyFilter) []store.KeyFilter {
	res := make([]store.KeyFilter, 0, len(fs))
	for _, f := range fs {
		res = append(res, store.KeyFilter{
			LifeCycleState: f.LifeCycleState,
			Status:         f.Status,
		})
	}
	return res
}

func mapKeyNotFoundErr(err error) error {
	if errors.Is(err, store.ErrKeyNotFound) {
		return ErrNoKeysFound
	}
	return err
}
