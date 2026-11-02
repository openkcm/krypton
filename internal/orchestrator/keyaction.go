package orchestrator

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/internal/keyoperator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

var (
	// ErrNoKeysFound signals that no keys were found in the key tree.
	ErrNoKeysFound = errors.New("keys not found")

	// ErrNoEligibleKeys signals that the key tree was non-empty but all
	// keys were already at the target state with completed processing;
	// no transition was required.
	ErrNoEligibleKeys = errors.New("no eligible keys found for processing")
)

// JobGroupPreparer prepares a job group for scheduling via orbital.
type JobGroupPreparer interface {
	PrepareJobGroup(ctx context.Context, group orbital.JobGroup) (orbital.JobGroup, error)
}

// KeyFilter constrains which keys are eligible for a key action based on
// lifecycle state and processing status.
type KeyFilter struct {
	LifeCycleState model.KeyLifeCycleState
	Status         []model.KeyProcessingStatus
}

// ApplyKeyActionRequest describes a key-tree action to apply: the target
// state, which keys match, and how to group the resulting orbital jobs.
type ApplyKeyActionRequest struct {
	TenantID   string
	KeyID      string
	KeyFilters []KeyFilter
	Cascading  bool
	// BottomUp, when true, iterates the key tree from leaves to root
	// (using IterKeysByLayerDsc) instead of the default root-to-leaf order.
	// Set to true when the action must reach leaves before their parents
	// (e.g. SuspendKey).
	BottomUp      bool
	HandlerConfig HandlerConfig
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
		ids := make([]KeyIdentifier, 0, len(layer))

		for _, key := range layer {
			// skipping keys that are already in the target state and have completed processing
			if key.LifeCycleState == action.HandlerConfig.toState && key.KeyProcessingState.Status == model.KeyProcessingCompleted {
				continue
			}

			// updating the key state to the target state and setting processing status to pending
			err := keyoperator.UpdateKeyState(key.TenantID, key.ID, keyoperator.Transition{
				FromLifeCycle:  []model.KeyLifeCycleState{key.LifeCycleState},
				ToLifeCycle:    action.HandlerConfig.toState,
				FromProcessing: []model.KeyProcessingStatus{key.KeyProcessingState.Status},
				ToProcessing:   model.KeyProcessingPending,
			})(ctx, stores)
			if err != nil {
				return orbital.JobGroup{}, fmt.Errorf("updating key %s state: %w", key.ID, err)
			}

			ids = append(ids, KeyIdentifier{
				ID:       key.ID,
				TenantID: key.TenantID,
			})
		}

		if len(ids) == 0 {
			continue
		}

		data, err := json.Marshal(KeyLayer{Identifiers: ids})
		if err != nil {
			return orbital.JobGroup{}, fmt.Errorf("%w: marshaling keys for job data: %w", ErrInternal, err)
		}

		jobs = append(jobs, orbital.NewJob(action.HandlerConfig.handlerType, data))
	}

	if len(jobs) == 0 {
		return orbital.JobGroup{}, fmt.Errorf("%w: no actionable keys found", ErrNoEligibleKeys)
	}

	return preparer.PrepareJobGroup(ctx, orbital.NewJobGroup(action.HandlerConfig.handlerType, jobs...))
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
