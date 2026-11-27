package orchestrator

import (
	"context"
	"encoding/json/v2"
	"fmt"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// ApplyRotationRequest identifies the key to rotate and whether to rotate its
// eligible descendants. Immediate children are resealed even without cascading.
type ApplyRotationRequest struct {
	TenantID  string
	KeyID     string
	Cascading bool
}

// ApplyRotation schedules rotation and resealing.
//
//	Non-cascading: Rotate L0 → Reseal L1
//	Cascading:     Rotate L0 → Reseal L1 → Rotate L1 → Reseal L2 → ...
//
// TODO: Make rotation requests idempotent.
func ApplyRotation(ctx context.Context, stores store.Stores, preparer JobGroupPreparer, action ApplyRotationRequest) (orbital.JobGroup, error) {
	layers, err := fetchRotationLayers(ctx, stores.Keys, action)
	if err != nil {
		return orbital.JobGroup{}, err
	}

	jobs, err := prepareRotationJobs(layers)
	if err != nil {
		return orbital.JobGroup{}, err
	}
	if len(jobs) == 0 {
		return orbital.JobGroup{}, fmt.Errorf("%w: no actionable keys found", ErrNoEligibleKeys)
	}

	return preparer.PrepareJobGroup(ctx, orbital.NewJobGroup(RotateKey, jobs...))
}

// prepareRotationJobs rotates each parent layer before resealing its children.
// The store query supplies eligible keys in execution order.
func prepareRotationJobs(layers []store.ParentChildKeyLayer) ([]orbital.Job, error) {
	var jobs []orbital.Job
	for _, layer := range layers {
		job, err := newKeyJob(RotateKey, layer.Parents)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, job)

		if len(layer.Children) > 0 {
			job, err := newKeyJob(ResealKey, layer.Children)
			if err != nil {
				return nil, err
			}
			jobs = append(jobs, job)
		}
	}

	return jobs, nil
}

func fetchRotationLayers(ctx context.Context, keyStore store.Key, action ApplyRotationRequest) ([]store.ParentChildKeyLayer, error) {
	query := store.GetParentChildKeyLayersQuery{
		TenantID: action.TenantID,
		KeyID:    action.KeyID,
		ParentFilters: []store.KeyFilter{
			{
				LifeCycleState: model.KeyLifeCycleActive,
				Status:         []model.KeyProcessingStatus{model.KeyProcessingCompleted},
			},
		},
		// Processing status alone does not establish whether material exists.
		ChildFilters: []store.KeyFilter{
			{LifeCycleState: model.KeyLifeCycleActive},
			{LifeCycleState: model.KeyLifeCycleSuspended},
			{LifeCycleState: model.KeyLifeCycleDeactivated},
			{LifeCycleState: model.KeyLifeCycleCompromised},
		},
	}
	if !action.Cascading {
		query.Depth = new(1) // One parent layer and its immediate children.
	}

	result, err := keyStore.GetParentChildKeyLayers(ctx, query)
	if err != nil {
		return nil, mapKeyNotFoundErr(err)
	}
	if len(result.Layers) == 0 || len(result.Layers[0].Parents) == 0 {
		return nil, ErrNoKeysFound
	}

	return result.Layers, nil
}

func newKeyJob(jobType string, keys []model.Key) (orbital.Job, error) {
	layer := KeyLayer{
		Identifiers: make([]KeyIdentifier, len(keys)),
	}
	for i, key := range keys {
		layer.Identifiers[i] = KeyIdentifier{
			ID:       key.ID,
			TenantID: key.TenantID,
		}
	}

	data, err := json.Marshal(layer)
	if err != nil {
		return orbital.Job{}, fmt.Errorf("%w: marshaling keys for job data: %w", ErrInternal, err)
	}
	return orbital.NewJob(jobType, data), nil
}
