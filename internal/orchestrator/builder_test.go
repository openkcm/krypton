package orchestrator_test

import (
	"testing"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/orchestrator"
)

func TestTaskDispatchRoutesByType(t *testing.T) {
	activate := &fakeTaskHandler{taskType: "activate"}
	rotate := &fakeTaskHandler{taskType: "rotate"}
	dispatch := orchestrator.NewTaskDispatch(map[string]orchestrator.OrbitalTaskHandler{
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
	dispatch := orchestrator.NewTaskDispatch(map[string]orchestrator.OrbitalTaskHandler{
		"activate": &fakeTaskHandler{taskType: "activate"},
	})

	resp := orbital.ExecuteHandler(t.Context(), dispatch, orbital.TaskRequest{TaskID: uuid.New(), Type: "mystery"})

	assert.Equal(t, "FAILED", resp.Status)
	assert.Contains(t, resp.ErrorMessage, orchestrator.NoTaskHandlerRegisteredMessage)
	assert.Contains(t, resp.ErrorMessage, "mystery")
}

func TestOrchestratorRegistersEmbeddedTarget(t *testing.T) {
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.OrbitalHandlers{
			TaskResolvers: []orchestrator.OrbitalTaskResolver{&fakeJobHandler{jobType: "job.type"}},
			TaskHandlers:  []orchestrator.OrbitalTaskHandler{&fakeTaskHandler{taskType: "activate"}},
		},
	)
	require.NoError(t, err)

	assert.Contains(t, orch.Targets(), orchestrator.DefaultLocalTargetName)
}

func TestBuildTaskHandlerMap(t *testing.T) {
	tests := []struct {
		name     string
		handlers []orchestrator.OrbitalTaskHandler
		wantErr  error
		wantLen  int
	}{
		{name: "empty returns error", handlers: nil, wantErr: orchestrator.ErrTaskHandlerRequired},
		{name: "single", handlers: []orchestrator.OrbitalTaskHandler{&fakeTaskHandler{taskType: "activate"}}, wantLen: 1},
		{name: "nil handler", handlers: []orchestrator.OrbitalTaskHandler{nil}, wantErr: orchestrator.ErrTaskHandlerNil},
		{name: "empty type", handlers: []orchestrator.OrbitalTaskHandler{&fakeTaskHandler{}}, wantErr: orchestrator.ErrTaskTypeEmpty},
		{
			name:     "duplicate",
			handlers: []orchestrator.OrbitalTaskHandler{&fakeTaskHandler{taskType: "dup"}, &fakeTaskHandler{taskType: "dup"}},
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
		handlers []orchestrator.OrbitalJobGroupHandler
		wantErr  error
		wantLen  int
	}{
		{name: "empty is ok", handlers: nil, wantLen: 0},
		{name: "single", handlers: []orchestrator.OrbitalJobGroupHandler{&fakeGroupHandler{groupType: "group"}}, wantLen: 1},
		{name: "nil handler", handlers: []orchestrator.OrbitalJobGroupHandler{nil}, wantErr: orchestrator.ErrGroupHandlerNil},
		{name: "empty type", handlers: []orchestrator.OrbitalJobGroupHandler{&fakeGroupHandler{}}, wantErr: orchestrator.ErrGroupTypeEmpty},
		{
			name:     "duplicate",
			handlers: []orchestrator.OrbitalJobGroupHandler{&fakeGroupHandler{groupType: "dup"}, &fakeGroupHandler{groupType: "dup"}},
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
