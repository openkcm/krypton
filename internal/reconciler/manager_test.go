package reconciler_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openkcm/orbital"
	"github.com/openkcm/orbital/store/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/reconciler"
)

func TestNewManager(t *testing.T) {
	var createdTargets []config.ReconcilerTarget
	targetProvider := reconciler.NewTargetProvider(func(_ context.Context, target config.ReconcilerTarget) (orbital.Initiator, error) {
		createdTargets = append(createdTargets, target)
		return &fakeInitiator{}, nil
	})

	cfg := config.ReconcilerConfig{MaxReconcileCount: 6}
	cfg.Targets = []config.ReconcilerTarget{validTarget("agent-aws"), validTarget("agent-gcp")}

	manager, err := reconciler.NewManager(t.Context(), &cfg, newNoopRepo(), targetProvider, []reconciler.JobHandler{&fakeJobHandler{jobType: "job.type"}})
	require.NoError(t, err)

	assert.Equal(t, cfg.MaxReconcileCount, manager.OrbitalManager().Config.MaxPendingReconciles)
	assert.Len(t, createdTargets, 2)
}

func TestNewManagerUsesDefaultMaxPendingReconciles(t *testing.T) {
	manager, err := reconciler.NewManager(
		t.Context(),
		new(config.ReconcilerConfig),
		newNoopRepo(),
		nil,
		[]reconciler.JobHandler{&fakeJobHandler{jobType: "job.type"}},
	)
	require.NoError(t, err)

	assert.Equal(t, reconciler.DefaultMaxPendingReconciles, manager.OrbitalManager().Config.MaxPendingReconciles)
}

func TestNewManagerOptions(t *testing.T) {
	manager, err := reconciler.NewManager(
		t.Context(),
		&config.ReconcilerConfig{},
		newNoopRepo(),
		nil,
		[]reconciler.JobHandler{&fakeJobHandler{jobType: "job.type"}},
		reconciler.WithMaxPendingReconciles(42),
		reconciler.WithConfirmJobAfter(3*time.Second),
		reconciler.WithExecInterval(250*time.Millisecond),
	)
	require.NoError(t, err)

	cfg := manager.OrbitalManager().Config
	assert.Equal(t, uint64(42), cfg.MaxPendingReconciles)
	assert.Equal(t, 3*time.Second, cfg.ConfirmJobAfter)
	assert.Equal(t, 250*time.Millisecond, cfg.ConfirmJobWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, cfg.CreateTasksWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, cfg.ReconcileWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, cfg.NotifyWorkerConfig.ExecInterval)
}

func TestNewManagerValidation(t *testing.T) {
	tests := []struct {
		name           string
		cfg            *config.ReconcilerConfig
		repo           *orbital.Repository
		targetProvider reconciler.TargetProvider
		handlers       []reconciler.JobHandler
		wantErr        error
	}{
		{
			name:     "nil config",
			repo:     newNoopRepo(),
			handlers: []reconciler.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			wantErr:  config.ErrReconcilerConfigNil,
		},
		{
			name:     "nil repo",
			cfg:      &config.ReconcilerConfig{},
			handlers: []reconciler.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			wantErr:  reconciler.ErrRepositoryNil,
		},
		{
			name:     "target factory required",
			cfg:      configWithTargets(),
			repo:     newNoopRepo(),
			handlers: []reconciler.JobHandler{&fakeJobHandler{jobType: "job.type"}},
			wantErr:  reconciler.ErrTargetFactoryRequired,
		},
		{
			name:    "handler required",
			cfg:     &config.ReconcilerConfig{},
			repo:    newNoopRepo(),
			wantErr: reconciler.ErrJobHandlerRequired,
		},
		{
			name:     "nil handler",
			cfg:      &config.ReconcilerConfig{},
			repo:     newNoopRepo(),
			handlers: []reconciler.JobHandler{nil},
			wantErr:  reconciler.ErrJobHandlerNil,
		},
		{
			name:     "empty handler type",
			cfg:      &config.ReconcilerConfig{},
			repo:     newNoopRepo(),
			handlers: []reconciler.JobHandler{&fakeJobHandler{}},
			wantErr:  reconciler.ErrJobTypeEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := reconciler.NewManager(t.Context(), tt.cfg, tt.repo, tt.targetProvider, tt.handlers)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestManagerRoutesJobHandler(t *testing.T) {
	handler := &fakeJobHandler{jobType: "job.type"}
	manager, err := reconciler.NewManager(t.Context(), &config.ReconcilerConfig{}, newNoopRepo(), nil, []reconciler.JobHandler{handler})
	require.NoError(t, err)

	confirmResult, err := manager.ConfirmJob(t.Context(), orbital.Job{Type: "job.type"})
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteJobConfirmer().Type(), confirmResult.Type())

	resolveResult, err := manager.ResolveTasks(t.Context(), orbital.Job{Type: "job.type"}, "")
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteTaskResolver().Type(), resolveResult.Type())

	assert.NoError(t, manager.JobDone(t.Context(), orbital.Job{Type: "job.type"}))
	assert.NoError(t, manager.JobFailed(t.Context(), orbital.Job{Type: "job.type"}))
	assert.NoError(t, manager.JobCanceled(t.Context(), orbital.Job{Type: "job.type"}))

	assert.True(t, handler.confirmed)
	assert.True(t, handler.resolved)
	assert.True(t, handler.done)
	assert.True(t, handler.failed)
	assert.True(t, handler.canceled)
}

func TestManagerUnknownJobTypeCancels(t *testing.T) {
	manager, err := reconciler.NewManager(t.Context(), &config.ReconcilerConfig{}, newNoopRepo(), nil, []reconciler.JobHandler{&fakeJobHandler{jobType: "known"}})
	require.NoError(t, err)

	confirmResult, err := manager.ConfirmJob(t.Context(), orbital.Job{Type: "unknown"})
	require.NoError(t, err)
	assert.Equal(t, orbital.CancelJobConfirmer("missing").Type(), confirmResult.Type())

	resolveResult, err := manager.ResolveTasks(t.Context(), orbital.Job{Type: "unknown"}, "")
	require.NoError(t, err)
	assert.Equal(t, orbital.CancelTaskResolver("missing").Type(), resolveResult.Type())

	assert.ErrorIs(t, manager.JobDone(t.Context(), orbital.Job{Type: "unknown"}), reconciler.ErrJobHandlerNotFound)
	assert.ErrorIs(t, manager.JobFailed(t.Context(), orbital.Job{Type: "unknown"}), reconciler.ErrJobHandlerNotFound)
	assert.ErrorIs(t, manager.JobCanceled(t.Context(), orbital.Job{Type: "unknown"}), reconciler.ErrJobHandlerNotFound)
	assert.Contains(t, reconciler.JobHandlerNotFoundError("unknown").Error(), reconciler.NoJobHandlerRegisteredMessage)
}

func TestBuildTargetsClosesCreatedClientsOnError(t *testing.T) {
	first := &fakeInitiator{}
	providerErr := errors.New("boom")
	targetProvider := reconciler.NewTargetProvider(func(_ context.Context, target config.ReconcilerTarget) (orbital.Initiator, error) {
		if target.Name == "first" {
			return first, nil
		}
		return nil, providerErr
	})

	targets := []config.ReconcilerTarget{validTarget("first"), validTarget("second")}
	_, err := reconciler.BuildTargets(t.Context(), targets, targetProvider)

	assert.ErrorIs(t, err, providerErr)
	assert.True(t, first.closed)
}

func TestStopClosesTargetsWhenOrbitalWasNotStarted(t *testing.T) {
	initiator := &fakeInitiator{}
	targetProvider := reconciler.NewTargetProvider(func(context.Context, config.ReconcilerTarget) (orbital.Initiator, error) {
		return initiator, nil
	})

	cfg := config.ReconcilerConfig{Targets: []config.ReconcilerTarget{validTarget("agent-aws")}}
	manager, err := reconciler.NewManager(t.Context(), &cfg, newNoopRepo(), targetProvider, []reconciler.JobHandler{&fakeJobHandler{jobType: "job.type"}})
	require.NoError(t, err)

	err = manager.Stop(t.Context())

	assert.ErrorIs(t, err, orbital.ErrManagerNotStarted)
	assert.True(t, initiator.closed)
	assert.Equal(t, 1, initiator.closeCount)
}

func configWithTargets() *config.ReconcilerConfig {
	return &config.ReconcilerConfig{
		Targets: []config.ReconcilerTarget{validTarget("agent-aws")},
	}
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

type fakeInitiator struct {
	closed     bool
	closeCount int
}

func (*fakeInitiator) SendTaskRequest(context.Context, orbital.TaskRequest) error {
	return nil
}

func (*fakeInitiator) ReceiveTaskResponse(ctx context.Context) (orbital.TaskResponse, error) {
	return orbital.TaskResponse{}, ctx.Err()
}

func (f *fakeInitiator) Close(context.Context) error {
	f.closed = true
	f.closeCount++
	return nil
}

func validTarget(name string) config.ReconcilerTarget {
	return config.ReconcilerTarget{Name: name, Address: "localhost:9091"}
}
