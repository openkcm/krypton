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

	"github.com/openkcm/krypton/internal/handler/activatekey"
	"github.com/openkcm/krypton/internal/keylifecycle"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type JobGroupPreparer interface {
	PrepareJobGroup(ctx context.Context, group orbital.JobGroup) (orbital.JobGroup, error)
}

type KeyTreeRetriever interface {
	KeyTree() (model.KeyTree, error)
}

// Transition holds the state transition inputs for UpdateKeyState.
type Transition struct {
	FromLifeCycle  []model.KeyLifeCycleState
	ToLifeCycle    model.KeyLifeCycleState
	FromProcessing []model.KeyProcessingStatus
	ToProcessing   model.KeyProcessingStatus
}

type FilterKeyTreeState struct {
	IsChildrenExcluded bool
	Tree               model.KeyTree
}

var _ KeyTreeRetriever = (*FilterKeyTreeState)(nil)

// KeyTree implements [KeyTreeRetriever].
func (f *FilterKeyTreeState) KeyTree() (model.KeyTree, error) {
	if f == nil || len(f.Tree) == 0 {
		return nil, ErrKeyTreeNotFound
	}
	return f.Tree, nil
}

type PrepareKeyTreeJobsState struct {
	JobGroup orbital.JobGroup
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

	// ErrKeyTreeNotFound signals that no keys were found in the key tree.
	ErrKeyTreeNotFound = errors.New("keyTree not found")

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

func NewFilterKeyTreeState() *FilterKeyTreeState {
	return &FilterKeyTreeState{}
}

func FilterKeyTree(tenantID, keyID string, toState model.KeyLifeCycleState, forStatus model.KeyProcessingStatus, ktstate *FilterKeyTreeState) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		if ktstate == nil {
			return fmt.Errorf("%w: filter key tree state must not be nil", ErrInternal)
		}
		// get all descendant keys and create kt for each layer
		kt, isExcluded, err := filterKeyTree(ctx, stores.Keys, tenantID, keyID, toState, forStatus)
		if err != nil {
			return err
		}

		if len(kt) == 0 {
			return ErrKeyTreeNotFound
		}

		ktstate.IsChildrenExcluded = isExcluded
		ktstate.Tree = kt

		return nil
	}
}

func UpdateKeyTree(ret KeyTreeRetriever, toState model.KeyLifeCycleState, toStatus model.KeyProcessingStatus) store.TransactionFunc {
	return func(ctx context.Context, stores store.Stores) error {
		if ret == nil {
			return fmt.Errorf("%w: key tree retriever is nil", ErrKeyTreeNotFound)
		}
		keytree, err := ret.KeyTree()
		if err != nil {
			return err
		}
		for _, layer := range keytree {
			for _, key := range layer {
				err := UpdateKeyState(key.TenantID, key.ID, Transition{
					FromLifeCycle:  []model.KeyLifeCycleState{key.LifeCycleState},
					ToLifeCycle:    toState,
					FromProcessing: []model.KeyProcessingStatus{key.KeyProcessingState.Status},
					ToProcessing:   toStatus,
				})(ctx, stores)
				if err != nil {
					return fmt.Errorf("updating key %s state: %w", key.ID, err)
				}
			}
		}
		return nil
	}
}

func NewPrepareKeyTreeJobsState() *PrepareKeyTreeJobsState {
	return &PrepareKeyTreeJobsState{}
}

func PrepareKeyTreeJobGroup(preparer JobGroupPreparer, ret KeyTreeRetriever, state *PrepareKeyTreeJobsState) store.TransactionFunc {
	return func(ctx context.Context, _ store.Stores) error {
		if ret == nil || preparer == nil || state == nil {
			return ErrInternal
		}
		keytree, err := ret.KeyTree()
		if err != nil {
			return err
		}
		jobs := make([]orbital.Job, 0, len(keytree))
		for _, layer := range keytree {
			data, err := json.Marshal(layer)
			if err != nil {
				return fmt.Errorf("%w: marshaling keys for job data: %w", ErrInternal, err)
			}
			jobs = append(jobs, orbital.NewJob(activatekey.JobType, data))
		}

		grp, err := preparer.PrepareJobGroup(ctx, orbital.NewJobGroup(activatekey.JobGroupType, jobs...))
		if err != nil {
			return fmt.Errorf("preparing job group: %w", err)
		}

		state.JobGroup = grp
		return nil
	}
}

func filterKeyTree(ctx context.Context, keyStore store.Key, tenantID, keyID string, toState model.KeyLifeCycleState, forStatus model.KeyProcessingStatus) (model.KeyTree, bool, error) {
	kt, err := keyStore.GetDescendantKeys(ctx, store.GetDescendantKeysQuery{
		KeyID:    keyID,
		TenantID: tenantID,
	})
	if err != nil {
		return nil, false, err
	}

	keyTree := model.KeyTree{}

	isExcludedKeyIDs := make(map[string]struct{})

	for layer := range kt.KeyTree.IterKeysByLayerAsc() {
		includedKeys := make([]model.Key, 0, len(layer))

		for _, key := range layer {
			if key.ParentID != nil {
				if _, ok := isExcludedKeyIDs[*key.ParentID]; ok {
					isExcludedKeyIDs[key.ID] = struct{}{}
					continue
				}
			}
			if key.KeyProcessingState.Status != forStatus {
				isExcludedKeyIDs[key.ID] = struct{}{}
				continue
			}
			if keylifecycle.ValidateTransition(key.LifeCycleState, toState) != nil {
				if key.LifeCycleState != toState {
					isExcludedKeyIDs[key.ID] = struct{}{}
					continue
				}
			}
			includedKeys = append(includedKeys, key)
		}

		if len(includedKeys) == 0 {
			continue
		}

		keyTree = append(keyTree, includedKeys)
	}
	return keyTree, len(isExcludedKeyIDs) != 0, nil
}
