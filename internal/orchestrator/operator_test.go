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

func TestOrchestratorRegistersEmbeddedTargetWhenTaskHandlerPresent(t *testing.T) {
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{
			Jobs:  []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			Tasks: []orchestrator.TaskHandler{&fakeTaskHandler{taskType: "activate"}},
		},
	)
	require.NoError(t, err)

	assert.Contains(t, orch.Targets(), orchestrator.DefaultLocalTargetName)
}

func TestOrchestratorAddsNoEmbeddedTargetWhenNoTaskHandler(t *testing.T) {
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{Jobs: []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}}},
	)
	require.NoError(t, err)

	assert.NotContains(t, orch.Targets(), orchestrator.DefaultLocalTargetName)
	assert.Empty(t, orch.Targets())
}

func TestOrchestratorUsesLocalTargetNameForEmbeddedOperator(t *testing.T) {
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{
			Jobs:  []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			Tasks: []orchestrator.TaskHandler{&fakeTaskHandler{taskType: "activate"}},
		},
		orchestrator.WithLocalTargetName("custom-embedded"),
	)
	require.NoError(t, err)

	assert.Equal(t, "custom-embedded", orch.LocalTarget())
	assert.Contains(t, orch.Targets(), "custom-embedded")
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
