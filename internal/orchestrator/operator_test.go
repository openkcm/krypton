package orchestrator_test

import (
	"context"
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/orchestrator"
)

func TestTaskDispatchRoutesByType(t *testing.T) {
	activate := &fakeTaskHandler{taskType: "activate"}
	rotate := &fakeTaskHandler{taskType: "rotate"}
	dispatch := orchestrator.NewTaskDispatch(map[string]orchestrator.TaskHandler{
		"activate": activate,
		"rotate":   rotate,
	})

	resp := orbital.ExecuteHandler(t.Context(), dispatch, orbital.TaskRequest{TaskID: uuid.New(), Type: "rotate"})

	assert.Equal(t, "DONE", resp.Status)
	assert.True(t, rotate.handled)
	assert.Equal(t, "rotate", rotate.gotType)
	assert.False(t, activate.handled)
}

func TestTaskDispatchUnknownTypeFails(t *testing.T) {
	dispatch := orchestrator.NewTaskDispatch(map[string]orchestrator.TaskHandler{
		"activate": &fakeTaskHandler{taskType: "activate"},
	})

	resp := orbital.ExecuteHandler(t.Context(), dispatch, orbital.TaskRequest{TaskID: uuid.New(), Type: "mystery"})

	assert.Equal(t, "FAILED", resp.Status)
	assert.Contains(t, resp.ErrorMessage, orchestrator.NoTaskHandlerRegisteredMessage)
	assert.Contains(t, resp.ErrorMessage, "mystery")
}

func TestManagerRegistersEmbeddedTargetWhenTaskHandlerPresent(t *testing.T) {
	manager, err := orchestrator.NewManager(
		t.Context(), &config.ReconcilerConfig{}, newNoopRepo(),
		orchestrator.Handlers{
			Jobs:  []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			Tasks: []orchestrator.TaskHandler{&fakeTaskHandler{taskType: "activate"}},
		},
	)
	require.NoError(t, err)

	assert.Contains(t, manager.Targets(), orchestrator.DefaultLocalTargetName)
}

func TestManagerAddsNoEmbeddedTargetWhenNoTaskHandler(t *testing.T) {
	manager, err := orchestrator.NewManager(
		t.Context(), &config.ReconcilerConfig{}, newNoopRepo(),
		orchestrator.Handlers{Jobs: []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}}},
	)
	require.NoError(t, err)

	assert.NotContains(t, manager.Targets(), orchestrator.DefaultLocalTargetName)
	assert.Empty(t, manager.Targets())
}

func TestManagerLocalTargetDuplicateClosesClients(t *testing.T) {
	initiator := &fakeInitiator{}
	targetProvider := orchestrator.NewTargetProvider(func(context.Context, config.ReconcilerTarget) (orbital.Initiator, error) {
		return initiator, nil
	})

	cfg := config.ReconcilerConfig{Targets: []config.ReconcilerTarget{validTarget("collides")}}
	_, err := orchestrator.NewManager(
		t.Context(), &cfg, newNoopRepo(),
		orchestrator.Handlers{
			Jobs:  []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			Tasks: []orchestrator.TaskHandler{&fakeTaskHandler{taskType: "activate"}},
		},
		orchestrator.WithTargetProvider(targetProvider),
		orchestrator.WithLocalTargetName("collides"),
	)

	assert.ErrorIs(t, err, orchestrator.ErrLocalTargetDuplicate)
	assert.True(t, initiator.closed)
}

func TestBuildTaskHandlerMap(t *testing.T) {
	tests := []struct {
		name     string
		handlers []orchestrator.TaskHandler
		wantErr  error
		wantLen  int
	}{
		{name: "empty is ok", handlers: nil, wantLen: 0},
		{name: "single", handlers: []orchestrator.TaskHandler{&fakeTaskHandler{taskType: "activate"}}, wantLen: 1},
		{name: "nil handler", handlers: []orchestrator.TaskHandler{nil}, wantErr: orchestrator.ErrTaskHandlerNil},
		{name: "empty type", handlers: []orchestrator.TaskHandler{&fakeTaskHandler{}}, wantErr: orchestrator.ErrTaskTypeEmpty},
		{
			name:     "duplicate",
			handlers: []orchestrator.TaskHandler{&fakeTaskHandler{taskType: "dup"}, &fakeTaskHandler{taskType: "dup"}},
			wantErr:  orchestrator.ErrTaskHandlerDuplicate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := orchestrator.BuildTaskHandlerMap(tt.handlers)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, result, tt.wantLen)
		})
	}
}

func TestBuildGroupHandlerMap(t *testing.T) {
	tests := []struct {
		name     string
		handlers []orchestrator.JobGroupHandler
		wantErr  error
		wantLen  int
	}{
		{name: "empty is ok", handlers: nil, wantLen: 0},
		{name: "single", handlers: []orchestrator.JobGroupHandler{&fakeGroupHandler{groupType: "group"}}, wantLen: 1},
		{name: "nil handler", handlers: []orchestrator.JobGroupHandler{nil}, wantErr: orchestrator.ErrGroupHandlerNil},
		{name: "empty type", handlers: []orchestrator.JobGroupHandler{&fakeGroupHandler{}}, wantErr: orchestrator.ErrGroupTypeEmpty},
		{
			name:     "duplicate",
			handlers: []orchestrator.JobGroupHandler{&fakeGroupHandler{groupType: "dup"}, &fakeGroupHandler{groupType: "dup"}},
			wantErr:  orchestrator.ErrGroupHandlerDuplicate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := orchestrator.BuildGroupHandlerMap(tt.handlers)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Len(t, result, tt.wantLen)
		})
	}
}
