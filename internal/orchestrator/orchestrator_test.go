package orchestrator_test

import (
	"context"
	"testing"
	"time"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/openkcm/orbital/store/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/orchestrator"
)

func TestNew(t *testing.T) {
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{Jobs: []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}}},
	)
	require.NoError(t, err)

	assert.Equal(t, orchestrator.DefaultMaxPendingReconciles, orch.OrbitalManager().Config.MaxPendingReconciles)
	assert.Equal(t, orchestrator.DefaultLocalTargetName, orch.LocalTarget())
}

func TestNewOptions(t *testing.T) {
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{Jobs: []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}}},
		orchestrator.WithMaxPendingReconciles(42),
		orchestrator.WithConfirmJobAfter(3*time.Second),
		orchestrator.WithExecInterval(250*time.Millisecond),
	)
	require.NoError(t, err)

	cfg := orch.OrbitalManager().Config
	assert.Equal(t, uint64(42), cfg.MaxPendingReconciles)
	assert.Equal(t, 3*time.Second, cfg.ConfirmJobAfter)
	assert.Equal(t, 250*time.Millisecond, cfg.ConfirmJobWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, cfg.CreateTasksWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, cfg.ReconcileWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, cfg.NotifyWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, cfg.NotifyJobGroupWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, cfg.ScheduleJobGroupWorkerConfig.ExecInterval)
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name     string
		repo     *orbital.Repository
		handlers orchestrator.Handlers
		opts     []orchestrator.Option
		wantErr  error
	}{
		{
			name:     "nil repo",
			handlers: orchestrator.Handlers{Jobs: []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}}},
			wantErr:  orchestrator.ErrRepositoryNil,
		},
		{
			name:    "job handler required",
			repo:    newNoopRepo(),
			wantErr: orchestrator.ErrJobHandlerRequired,
		},
		{
			name:     "nil job handler",
			repo:     newNoopRepo(),
			handlers: orchestrator.Handlers{Jobs: []orchestrator.JobHandler{nil}},
			wantErr:  orchestrator.ErrJobHandlerNil,
		},
		{
			name:     "empty job handler type",
			repo:     newNoopRepo(),
			handlers: orchestrator.Handlers{Jobs: []orchestrator.JobHandler{&fakeJobHandler{}}},
			wantErr:  orchestrator.ErrJobTypeEmpty,
		},
		{
			name: "duplicate job handler",
			repo: newNoopRepo(),
			handlers: orchestrator.Handlers{Jobs: []orchestrator.JobHandler{
				&fakeJobHandler{jobType: "dup"}, &fakeJobHandler{jobType: "dup"},
			}},
			wantErr: orchestrator.ErrJobHandlerDuplicate,
		},
		{
			name: "nil task handler",
			repo: newNoopRepo(),
			handlers: orchestrator.Handlers{
				Jobs:  []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
				Tasks: []orchestrator.TaskHandler{nil},
			},
			wantErr: orchestrator.ErrTaskHandlerNil,
		},
		{
			name: "nil group handler",
			repo: newNoopRepo(),
			handlers: orchestrator.Handlers{
				Jobs:   []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
				Groups: []orchestrator.JobGroupHandler{nil},
			},
			wantErr: orchestrator.ErrGroupHandlerNil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := orchestrator.New(t.Context(), tt.repo, tt.handlers, tt.opts...)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestOrchestratorRoutesJobHandler(t *testing.T) {
	handler := &fakeJobHandler{jobType: "job.type"}
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{Jobs: []orchestrator.JobHandler{handler}},
	)
	require.NoError(t, err)

	confirmResult, err := orch.ConfirmJob(t.Context(), orbital.Job{Type: "job.type"})
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteJobConfirmer().Type(), confirmResult.Type())

	resolveResult, err := orch.ResolveTasks(t.Context(), orbital.Job{Type: "job.type"}, "")
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteTaskResolver().Type(), resolveResult.Type())

	assert.NoError(t, orch.JobDone(t.Context(), orbital.Job{Type: "job.type"}))
	assert.NoError(t, orch.JobFailed(t.Context(), orbital.Job{Type: "job.type"}))
	assert.NoError(t, orch.JobCanceled(t.Context(), orbital.Job{Type: "job.type"}))

	assert.True(t, handler.confirmed)
	assert.True(t, handler.resolved)
	assert.True(t, handler.done)
	assert.True(t, handler.failed)
	assert.True(t, handler.canceled)
}

func TestOrchestratorUnknownJobTypeCancels(t *testing.T) {
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{Jobs: []orchestrator.JobHandler{&fakeJobHandler{jobType: "known"}}},
	)
	require.NoError(t, err)

	confirmResult, err := orch.ConfirmJob(t.Context(), orbital.Job{Type: "unknown"})
	require.NoError(t, err)
	assert.Equal(t, orbital.CancelJobConfirmer("missing").Type(), confirmResult.Type())

	resolveResult, err := orch.ResolveTasks(t.Context(), orbital.Job{Type: "unknown"}, "")
	require.NoError(t, err)
	assert.Equal(t, orbital.CancelTaskResolver("missing").Type(), resolveResult.Type())

	assert.ErrorIs(t, orch.JobDone(t.Context(), orbital.Job{Type: "unknown"}), orchestrator.ErrJobHandlerNotFound)
	assert.ErrorIs(t, orch.JobFailed(t.Context(), orbital.Job{Type: "unknown"}), orchestrator.ErrJobHandlerNotFound)
	assert.ErrorIs(t, orch.JobCanceled(t.Context(), orbital.Job{Type: "unknown"}), orchestrator.ErrJobHandlerNotFound)
	assert.Contains(t, orchestrator.JobHandlerNotFoundError("unknown").Error(), orchestrator.NoJobHandlerRegisteredMessage)
}

func TestOrchestratorRoutesJobGroupHandler(t *testing.T) {
	group := &fakeGroupHandler{groupType: "group.type"}
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{
			Jobs:   []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			Groups: []orchestrator.JobGroupHandler{group},
		},
	)
	require.NoError(t, err)

	// noopStore reports the group as not found, so dispatch falls back to the
	// group orbital handed us and the handler still fires.
	jg := orbital.JobGroup{ID: uuid.New(), Type: "group.type"}
	require.NoError(t, orch.JobGroupDone(t.Context(), jg))
	require.NoError(t, orch.JobGroupFailed(t.Context(), jg))
	require.NoError(t, orch.JobGroupCanceled(t.Context(), jg))

	assert.True(t, group.done)
	assert.True(t, group.failed)
	assert.True(t, group.canceled)
	assert.Equal(t, jg.ID, group.lastGroup.ID)
}

func TestOrchestratorUnknownJobGroupTypeIsNoop(t *testing.T) {
	group := &fakeGroupHandler{groupType: "known.group"}
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{
			Jobs:   []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			Groups: []orchestrator.JobGroupHandler{group},
		},
	)
	require.NoError(t, err)

	assert.NoError(t, orch.JobGroupDone(t.Context(), orbital.JobGroup{Type: "unknown.group"}))
	assert.NoError(t, orch.JobGroupFailed(t.Context(), orbital.JobGroup{Type: "unknown.group"}))
	assert.NoError(t, orch.JobGroupCanceled(t.Context(), orbital.JobGroup{Type: "unknown.group"}))

	assert.False(t, group.done)
	assert.False(t, group.failed)
	assert.False(t, group.canceled)
}

func TestStopReturnsErrorWhenOrbitalNotStarted(t *testing.T) {
	orch, err := orchestrator.New(
		t.Context(), newNoopRepo(),
		orchestrator.Handlers{
			Jobs:  []orchestrator.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			Tasks: []orchestrator.TaskHandler{&fakeTaskHandler{taskType: "activate"}},
		},
	)
	require.NoError(t, err)

	err = orch.Stop(t.Context())

	assert.ErrorIs(t, err, orbital.ErrManagerNotStarted)
}

func newNoopRepo() *orbital.Repository {
	return orbital.NewRepository(noopStore{})
}

type fakeJobHandler struct {
	jobType   string
	confirmed bool
	resolved  bool
	done      bool
	failed    bool
	canceled  bool
}

func (f *fakeJobHandler) JobType() string {
	return f.jobType
}

func (f *fakeJobHandler) ConfirmJob(context.Context, orbital.Job) (orbital.JobConfirmerResult, error) {
	f.confirmed = true
	return orbital.CompleteJobConfirmer(), nil
}

func (f *fakeJobHandler) ResolveTasks(context.Context, orbital.Job, orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	f.resolved = true
	return orbital.CompleteTaskResolver().WithTaskInfo([]orbital.TaskInfo{{Type: "task.type", Target: "root"}}), nil
}

func (f *fakeJobHandler) OnJobDone(context.Context, orbital.Job) error {
	f.done = true
	return nil
}

func (f *fakeJobHandler) OnJobFailed(context.Context, orbital.Job) error {
	f.failed = true
	return nil
}

func (f *fakeJobHandler) OnJobCanceled(context.Context, orbital.Job) error {
	f.canceled = true
	return nil
}

type fakeGroupHandler struct {
	groupType string
	done      bool
	failed    bool
	canceled  bool
	lastGroup orbital.JobGroup
}

func (f *fakeGroupHandler) JobGroupType() string {
	return f.groupType
}

func (f *fakeGroupHandler) OnJobGroupDone(_ context.Context, group orbital.JobGroup) error {
	f.done = true
	f.lastGroup = group
	return nil
}

func (f *fakeGroupHandler) OnJobGroupFailed(_ context.Context, group orbital.JobGroup) error {
	f.failed = true
	f.lastGroup = group
	return nil
}

func (f *fakeGroupHandler) OnJobGroupCanceled(_ context.Context, group orbital.JobGroup) error {
	f.canceled = true
	f.lastGroup = group
	return nil
}

type fakeTaskHandler struct {
	taskType string
	handled  bool
	gotType  string
}

func (f *fakeTaskHandler) TaskType() string {
	return f.taskType
}

func (f *fakeTaskHandler) Handle(_ context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
	f.handled = true
	f.gotType = req.TaskType
	resp.Complete()
}

type noopStore struct{}

func (noopStore) Create(_ context.Context, entities ...orbital.Entity) ([]orbital.Entity, error) {
	return entities, nil
}

func (noopStore) Update(_ context.Context, entities ...orbital.Entity) ([]orbital.Entity, error) {
	return entities, nil
}

func (noopStore) Find(context.Context, query.Query) (orbital.FindResult, error) {
	return orbital.FindResult{}, nil
}

func (noopStore) List(context.Context, query.Query) (orbital.ListResult, error) {
	return orbital.ListResult{}, nil
}

func (s noopStore) Transaction(ctx context.Context, txFunc orbital.TransactionFunc) error {
	return txFunc(ctx, *orbital.NewRepository(s))
}
