package reconciler

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/openkcm/orbital"
	"github.com/openkcm/orbital/store/query"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/config"
)

func TestNewManager(t *testing.T) {
	var createdTargets []config.ReconcilerTarget
	factory := TargetClientFactoryFunc(func(_ context.Context, target config.ReconcilerTarget) (orbital.Initiator, error) {
		createdTargets = append(createdTargets, target)
		return &fakeInitiator{}, nil
	})

	cfg := config.ReconcilerConfig{MaxReconcileCount: 6}
	cfg.Targets = []config.ReconcilerTarget{validTarget("agent-aws"), validTarget("agent-gcp")}

	manager, err := NewManager(t.Context(), &cfg, newNoopRepo(), factory, []JobHandler{&fakeJobHandler{jobType: "job.type"}})
	require.NoError(t, err)

	assert.Equal(t, cfg.MaxReconcileCount, manager.orbitalManager.Config.MaxPendingReconciles)
	assert.Len(t, createdTargets, 2)
}

func TestNewManagerUsesDefaultMaxPendingReconciles(t *testing.T) {
	manager, err := NewManager(
		t.Context(),
		new(config.ReconcilerConfig),
		newNoopRepo(),
		nil,
		[]JobHandler{&fakeJobHandler{jobType: "job.type"}},
	)
	require.NoError(t, err)

	assert.Equal(t, defaultMaxPendingReconciles, manager.orbitalManager.Config.MaxPendingReconciles)
}

func TestNewManagerOptions(t *testing.T) {
	manager, err := NewManager(
		t.Context(),
		&config.ReconcilerConfig{},
		newNoopRepo(),
		nil,
		[]JobHandler{&fakeJobHandler{jobType: "job.type"}},
		WithMaxPendingReconciles(42),
		WithConfirmJobAfter(3*time.Second),
		WithExecInterval(250*time.Millisecond),
	)
	require.NoError(t, err)

	assert.Equal(t, uint64(42), manager.orbitalManager.Config.MaxPendingReconciles)
	assert.Equal(t, 3*time.Second, manager.orbitalManager.Config.ConfirmJobAfter)
	assert.Equal(t, 250*time.Millisecond, manager.orbitalManager.Config.ConfirmJobWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, manager.orbitalManager.Config.CreateTasksWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, manager.orbitalManager.Config.ReconcileWorkerConfig.ExecInterval)
	assert.Equal(t, 250*time.Millisecond, manager.orbitalManager.Config.NotifyWorkerConfig.ExecInterval)
}

func TestNewManagerValidation(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *config.ReconcilerConfig
		repo     *orbital.Repository
		factory  TargetClientFactory
		handlers []JobHandler
		wantErr  error
	}{
		{
			name:     "nil config",
			repo:     newNoopRepo(),
			handlers: []JobHandler{&fakeJobHandler{jobType: "job.type"}},
			wantErr:  config.ErrReconcilerConfigNil,
		},
		{
			name:     "nil repo",
			cfg:      &config.ReconcilerConfig{},
			handlers: []JobHandler{&fakeJobHandler{jobType: "job.type"}},
			wantErr:  ErrRepositoryNil,
		},
		{
			name:     "target factory required",
			cfg:      configWithTargets(),
			repo:     newNoopRepo(),
			handlers: []JobHandler{&fakeJobHandler{jobType: "job.type"}},
			wantErr:  ErrTargetFactoryRequired,
		},
		{
			name:    "handler required",
			cfg:     &config.ReconcilerConfig{},
			repo:    newNoopRepo(),
			wantErr: ErrJobHandlerRequired,
		},
		{
			name:     "nil handler",
			cfg:      &config.ReconcilerConfig{},
			repo:     newNoopRepo(),
			handlers: []JobHandler{nil},
			wantErr:  ErrJobHandlerNil,
		},
		{
			name:     "empty handler type",
			cfg:      &config.ReconcilerConfig{},
			repo:     newNoopRepo(),
			handlers: []JobHandler{&fakeJobHandler{}},
			wantErr:  ErrJobTypeEmpty,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewManager(t.Context(), tt.cfg, tt.repo, tt.factory, tt.handlers)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestManagerRoutesJobHandler(t *testing.T) {
	handler := &fakeJobHandler{jobType: "job.type"}
	manager, err := NewManager(t.Context(), &config.ReconcilerConfig{}, newNoopRepo(), nil, []JobHandler{handler})
	require.NoError(t, err)

	confirmResult, err := manager.confirmJob(t.Context(), orbital.Job{Type: "job.type"})
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteJobConfirmer().Type(), confirmResult.Type())

	resolveResult, err := manager.resolveTasks(t.Context(), orbital.Job{Type: "job.type"}, "")
	require.NoError(t, err)
	assert.Equal(t, orbital.CompleteTaskResolver().Type(), resolveResult.Type())

	assert.NoError(t, manager.jobDone(t.Context(), orbital.Job{Type: "job.type"}))
	assert.NoError(t, manager.jobFailed(t.Context(), orbital.Job{Type: "job.type"}))
	assert.NoError(t, manager.jobCanceled(t.Context(), orbital.Job{Type: "job.type"}))

	assert.True(t, handler.confirmed)
	assert.True(t, handler.resolved)
	assert.True(t, handler.done)
	assert.True(t, handler.failed)
	assert.True(t, handler.canceled)
}

func TestManagerUnknownJobTypeCancels(t *testing.T) {
	manager, err := NewManager(t.Context(), &config.ReconcilerConfig{}, newNoopRepo(), nil, []JobHandler{&fakeJobHandler{jobType: "known"}})
	require.NoError(t, err)

	confirmResult, err := manager.confirmJob(t.Context(), orbital.Job{Type: "unknown"})
	require.NoError(t, err)
	assert.Equal(t, orbital.CancelJobConfirmer("missing").Type(), confirmResult.Type())

	resolveResult, err := manager.resolveTasks(t.Context(), orbital.Job{Type: "unknown"}, "")
	require.NoError(t, err)
	assert.Equal(t, orbital.CancelTaskResolver("missing").Type(), resolveResult.Type())

	assert.ErrorIs(t, manager.jobDone(t.Context(), orbital.Job{Type: "unknown"}), ErrJobHandlerNotFound)
	assert.ErrorIs(t, manager.jobFailed(t.Context(), orbital.Job{Type: "unknown"}), ErrJobHandlerNotFound)
	assert.ErrorIs(t, manager.jobCanceled(t.Context(), orbital.Job{Type: "unknown"}), ErrJobHandlerNotFound)
	assert.Contains(t, jobHandlerNotFoundError("unknown").Error(), noJobHandlerRegisteredMessage)
}

func TestBuildTargetsClosesCreatedClientsOnError(t *testing.T) {
	first := &fakeInitiator{}
	factoryErr := errors.New("boom")
	factory := TargetClientFactoryFunc(func(_ context.Context, target config.ReconcilerTarget) (orbital.Initiator, error) {
		if target.Name == "first" {
			return first, nil
		}
		return nil, factoryErr
	})

	targets := []config.ReconcilerTarget{validTarget("first"), validTarget("second")}
	_, err := buildTargets(t.Context(), targets, factory)

	assert.ErrorIs(t, err, factoryErr)
	assert.True(t, first.closed)
}

func TestStopClosesTargetsWhenOrbitalWasNotStarted(t *testing.T) {
	initiator := &fakeInitiator{}
	factory := TargetClientFactoryFunc(func(context.Context, config.ReconcilerTarget) (orbital.Initiator, error) {
		return initiator, nil
	})

	cfg := config.ReconcilerConfig{Targets: []config.ReconcilerTarget{validTarget("agent-aws")}}
	manager, err := NewManager(t.Context(), &cfg, newNoopRepo(), factory, []JobHandler{&fakeJobHandler{jobType: "job.type"}})
	require.NoError(t, err)

	err = manager.Stop(t.Context())

	assert.ErrorIs(t, err, orbital.ErrManagerNotStarted)
	assert.True(t, initiator.closed)
	assert.Equal(t, 1, initiator.closeCount)
}

func TestManagerOnlyExposesStartAndStop(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "manager.go", nil, 0)
	require.NoError(t, err)

	exported := map[string]struct{}{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || !fn.Name.IsExported() {
			continue
		}
		if len(fn.Recv.List) == 0 {
			continue
		}
		star, ok := fn.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		ident, ok := star.X.(*ast.Ident)
		if ok && ident.Name == "Manager" {
			exported[fn.Name.Name] = struct{}{}
		}
	}

	assert.Equal(t, map[string]struct{}{"Start": {}, "Stop": {}}, exported)
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
