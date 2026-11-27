package orchestrator_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/orchestrator"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	storesql "github.com/openkcm/krypton/pkg/store/sql"
)

func TestApplyRotation(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	ks := storesql.NewKeyStore(db)
	a := seedKey(t, ks, tenant.ID, "A", "K0", nil, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
	b := seedKey(t, ks, tenant.ID, "B", "K1", &a.ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
	c := seedKey(t, ks, tenant.ID, "C", "K1", &a.ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
	d := seedKey(t, ks, tenant.ID, "D", "K2", &b.ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
	e := seedKey(t, ks, tenant.ID, "E", "K2", &c.ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
	f := seedKey(t, ks, tenant.ID, "F", "K1", &a.ID, model.KeyLifeCycleSuspended, model.KeyProcessingCompleted)
	seedKey(t, ks, tenant.ID, "G", "K2", &f.ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)

	tests := []struct {
		name      string
		keyID     string
		cascading bool
		types     []string
		keys      [][]string
	}{
		{
			name:  "leaf",
			keyID: d.ID,
			types: []string{orchestrator.RotateKey},
			keys:  [][]string{{d.ID}},
		},
		{
			name:  "non-cascading",
			keyID: a.ID,
			types: []string{orchestrator.RotateKey, orchestrator.ResealKey},
			keys:  [][]string{{a.ID}, {b.ID, c.ID, f.ID}},
		},
		{
			name:      "cascading",
			keyID:     a.ID,
			cascading: true,
			types: []string{
				orchestrator.RotateKey, orchestrator.ResealKey,
				orchestrator.RotateKey, orchestrator.ResealKey, orchestrator.RotateKey,
			},
			keys: [][]string{{a.ID}, {b.ID, c.ID, f.ID}, {b.ID, c.ID}, {d.ID, e.ID}, {d.ID, e.ID}},
		},
	}
	resolvers := map[string]*orchestrator.TaskResolver{
		orchestrator.RotateKey: orchestrator.NewTaskResolver(orchestrator.RotateHandlerConfig()),
		orchestrator.ResealKey: orchestrator.NewTaskResolver(orchestrator.ResealHandlerConfig()),
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var queries []store.GetParentChildKeyLayersQuery
			// Only the tree query is delegated; unexpected reads or mutations fail.
			keyStore := &rotationTreeStore{fetch: func(ctx context.Context, query store.GetParentChildKeyLayersQuery) (store.GetParentChildKeyLayersResult, error) {
				queries = append(queries, query)
				return ks.GetParentChildKeyLayers(ctx, query)
			}}
			preparer := &recordingPreparer{}
			group, err := orchestrator.ApplyRotation(t.Context(), store.Stores{Keys: keyStore}, preparer, orchestrator.ApplyRotationRequest{
				TenantID:  tenant.ID,
				KeyID:     tc.keyID,
				Cascading: tc.cascading,
			})
			require.NoError(t, err)
			require.Len(t, queries, 1)
			assert.Equal(t, tenant.ID, queries[0].TenantID)
			assert.Equal(t, tc.keyID, queries[0].KeyID)
			assert.Equal(t, []store.KeyFilter{
				{LifeCycleState: model.KeyLifeCycleActive},
				{LifeCycleState: model.KeyLifeCycleSuspended},
				{LifeCycleState: model.KeyLifeCycleDeactivated},
				{LifeCycleState: model.KeyLifeCycleCompromised},
			}, queries[0].ChildFilters)
			assert.Equal(t, []store.KeyFilter{{LifeCycleState: model.KeyLifeCycleActive, Status: []model.KeyProcessingStatus{model.KeyProcessingCompleted}}}, queries[0].ParentFilters)
			if tc.cascading {
				assert.Nil(t, queries[0].Depth)
			} else {
				require.NotNil(t, queries[0].Depth)
				assert.Equal(t, 1, *queries[0].Depth)
			}
			assert.Equal(t, 1, preparer.calls)
			assert.Equal(t, orchestrator.RotateKey, group.Type)
			require.Len(t, group.Jobs, len(tc.types))
			for i, job := range group.Jobs {
				assert.Equal(t, tc.types[i], job.Type)
				assertJobDataContainsKeys(t, job.Data, tc.keys[i]...)
				assertJobDataTenantID(t, job.Data, tenant.ID)

				// Scheduled jobs must fan out through the shared KeyLayer resolver.
				resolver := resolvers[job.Type]
				require.NotNil(t, resolver)
				assert.Equal(t, job.Type, resolver.JobType())
				result, err := resolver.ResolveTasks(t.Context(), job, orbital.TaskResolverCursor(""))
				require.NoError(t, err)
				var layer orchestrator.KeyLayer
				require.NoError(t, json.Unmarshal(job.Data, &layer))
				infos := make([]orbital.TaskInfo, 0, len(layer.Identifiers))
				for _, id := range layer.Identifiers {
					data, err := json.Marshal(id)
					require.NoError(t, err)
					infos = append(infos, orbital.TaskInfo{
						Data: data, Type: job.Type, Target: orchestrator.DefaultLocalTargetName,
					})
				}
				assert.Equal(t, orbital.CompleteTaskResolver().WithTaskInfo(infos), result)
			}
		})
	}
}

func TestApplyRotationChildEligibility(t *testing.T) {
	db := newRootDB(t)
	tenant := createTenant(t, db)
	ks := storesql.NewKeyStore(db)
	for _, state := range []model.KeyLifeCycleState{
		model.KeyLifeCycleActive, model.KeyLifeCycleSuspended,
		model.KeyLifeCycleDeactivated, model.KeyLifeCycleCompromised,
		model.KeyLifeCyclePreActivation, model.KeyLifeCycleDestroyed,
	} {
		for _, status := range []model.KeyProcessingStatus{
			model.KeyProcessingCompleted, model.KeyProcessingPending,
			model.KeyProcessingFailed, model.KeyProcessingInProgress,
		} {
			t.Run(string(state)+"/"+string(status), func(t *testing.T) {
				a := seedKey(t, ks, tenant.ID, t.Name()+"-A", "K0", nil, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
				b := seedKey(t, ks, tenant.ID, t.Name()+"-B", "K1", &a.ID, state, status)
				d := seedKey(t, ks, tenant.ID, t.Name()+"-D", "K2", &b.ID, model.KeyLifeCycleActive, model.KeyProcessingCompleted)
				for _, cascading := range []bool{false, true} {
					group, err := orchestrator.ApplyRotation(t.Context(), store.Stores{Keys: ks}, &stubPreparer{}, orchestrator.ApplyRotationRequest{
						TenantID: tenant.ID, KeyID: a.ID, Cascading: cascading,
					})
					require.NoError(t, err)
					rotates := state == model.KeyLifeCycleActive && status == model.KeyProcessingCompleted
					reseals := state == model.KeyLifeCycleActive || state == model.KeyLifeCycleSuspended || state == model.KeyLifeCycleDeactivated || state == model.KeyLifeCycleCompromised
					wantJobs := 1
					if reseals {
						wantJobs = 2
					}
					if rotates && cascading {
						wantJobs = 5
					}
					require.Len(t, group.Jobs, wantJobs, "cascading=%v", cascading)
					assert.Equal(t, orchestrator.RotateKey, group.Jobs[0].Type)
					assertJobDataContainsKeys(t, group.Jobs[0].Data, a.ID)
					if reseals {
						assert.Equal(t, orchestrator.ResealKey, group.Jobs[1].Type)
						assertJobDataContainsKeys(t, group.Jobs[1].Data, b.ID)
						assertJobDataTenantID(t, group.Jobs[1].Data, tenant.ID)
					}
					if rotates && cascading {
						assert.Equal(t, orchestrator.RotateKey, group.Jobs[2].Type)
						assertJobDataContainsKeys(t, group.Jobs[2].Data, b.ID)
						assert.Equal(t, orchestrator.ResealKey, group.Jobs[3].Type)
						assert.Equal(t, orchestrator.RotateKey, group.Jobs[4].Type)
						assertJobDataContainsKeys(t, group.Jobs[4].Data, d.ID)
					}
					for _, original := range []model.Key{a, b, d} {
						key, err := ks.GetKeyByID(t.Context(), original.ID, tenant.ID)
						require.NoError(t, err)
						assert.Equal(t, original.LifeCycleState, key.LifeCycleState)
						assert.Equal(t, original.KeyProcessingState, key.KeyProcessingState)
					}
				}
			})
		}
	}
}

func TestApplyRotationFetchErrors(t *testing.T) {
	fetchErr := errors.New("fetch failed")
	tests := []struct {
		name   string
		layers []store.ParentChildKeyLayer
		err    error
		want   error
	}{
		{name: "not found", err: store.ErrKeyNotFound, want: orchestrator.ErrNoKeysFound},
		{name: "store error", err: fetchErr, want: fetchErr},
		{name: "nil layers", want: orchestrator.ErrNoKeysFound},
		{name: "empty layers", layers: []store.ParentChildKeyLayer{}, want: orchestrator.ErrNoKeysFound},
		{name: "empty parents", layers: []store.ParentChildKeyLayer{{}}, want: orchestrator.ErrNoKeysFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyStore := &rotationTreeStore{fetch: func(_ context.Context, _ store.GetParentChildKeyLayersQuery) (store.GetParentChildKeyLayersResult, error) {
				return store.GetParentChildKeyLayersResult{Layers: tc.layers}, tc.err
			}}
			preparer := &recordingPreparer{}
			group, err := orchestrator.ApplyRotation(t.Context(), store.Stores{Keys: keyStore}, preparer, orchestrator.ApplyRotationRequest{
				TenantID: uuid.New().String(), KeyID: uuid.New().String(),
			})
			assert.ErrorIs(t, err, tc.want)
			assert.Empty(t, group)
			assert.Zero(t, preparer.calls)
		})
	}
}

// Embedding an uninitialized store makes unexpected reads or mutations fail.
type rotationTreeStore struct {
	store.Key

	fetch func(context.Context, store.GetParentChildKeyLayersQuery) (store.GetParentChildKeyLayersResult, error)
}

func (s *rotationTreeStore) GetParentChildKeyLayers(ctx context.Context, query store.GetParentChildKeyLayersQuery) (store.GetParentChildKeyLayersResult, error) {
	return s.fetch(ctx, query)
}

type recordingPreparer struct {
	calls int
}

func (p *recordingPreparer) PrepareJobGroup(_ context.Context, group orbital.JobGroup) (orbital.JobGroup, error) {
	p.calls++
	return group, nil
}
