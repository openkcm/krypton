package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/openkcm/orbital/client/embedded"

	"github.com/openkcm/krypton/internal/config"
)

const (
	noJobHandlerRegisteredMessage        = "no job handler registered for job type"
	defaultMaxPendingReconciles   uint64 = 10
	defaultEmbeddedHandlerTimeout        = 90 * time.Second
)

var (
	ErrRepositoryNil         = errors.New("orbital repository cannot be nil")
	ErrTargetFactoryRequired = errors.New("target client factory is required when targets are configured")
	ErrJobHandlerRequired    = errors.New("at least one job handler is required")
	ErrJobHandlerNil         = errors.New("job handler cannot be nil")
	ErrJobTypeEmpty          = errors.New("job handler type cannot be empty")
	ErrJobHandlerDuplicate   = errors.New("duplicate job handler")
	ErrTargetClientNil       = errors.New("target client cannot be nil")
	ErrJobHandlerNotFound    = errors.New(noJobHandlerRegisteredMessage)
)

// TargetProvider builds an orbital initiator for a configured rpc target.
type TargetProvider func(context.Context, config.ReconcilerTarget) (orbital.Initiator, error)

type builderOptions struct {
	targetProvider         TargetProvider
	localTargetName        string
	embeddedBufferSize     int
	embeddedHandlerTimeout time.Duration
	orbitalMutators        []func(*orbital.Manager)
}

// Manager owns the orbital manager lifecycle plus the embedded operator for a
// Krypton process. It routes orbital's job, job-group, and task callbacks to the
// registered handlers.
type Manager struct {
	repo           *orbital.Repository
	orbitalManager *orbital.Manager
	jobHandlers    map[string]JobHandler
	groupHandlers  map[string]JobGroupHandler
	taskHandlers   map[string]TaskHandler
	targets        map[string]orbital.TargetManager
	localTarget    string
}

// NewManager wires the registered handlers, target clients, the embedded
// operator (only when at least one task handler is registered), and orbital
// worker config.
func NewManager(
	ctx context.Context,
	cfg *config.ReconcilerConfig,
	repo *orbital.Repository,
	handlers Handlers,
	opts ...Option,
) (*Manager, error) {
	if cfg == nil {
		return nil, config.ErrReconcilerConfigNil
	}
	if repo == nil {
		return nil, ErrRepositoryNil
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	options := builderOptions{
		localTargetName:        DefaultLocalTargetName,
		embeddedBufferSize:     defaultEmbeddedBufferSize,
		embeddedHandlerTimeout: defaultEmbeddedHandlerTimeout,
	}
	for _, opt := range opts {
		opt(&options)
	}

	jobHandlers, err := buildJobHandlerMap(handlers.Jobs)
	if err != nil {
		return nil, err
	}
	groupHandlers, err := buildGroupHandlerMap(handlers.Groups)
	if err != nil {
		return nil, err
	}
	taskHandlers, err := buildTaskHandlerMap(handlers.Tasks)
	if err != nil {
		return nil, err
	}

	targets, err := buildTargets(ctx, cfg.Targets, options.targetProvider)
	if err != nil {
		return nil, err
	}

	manager := &Manager{
		repo:          repo,
		jobHandlers:   jobHandlers,
		groupHandlers: groupHandlers,
		taskHandlers:  taskHandlers,
		targets:       targets,
		localTarget:   options.localTargetName,
	}

	if len(taskHandlers) > 0 {
		if err := manager.addEmbeddedTarget(ctx, options); err != nil {
			return nil, err
		}
	}

	orbitalOpts := []orbital.ManagerOptsFunc{
		orbital.WithTargets(targets),
		orbital.WithJobConfirmFunc(manager.confirmJob),
		orbital.WithJobDoneEventFunc(manager.jobDone),
		orbital.WithJobFailedEventFunc(manager.jobFailed),
		orbital.WithJobCanceledEventFunc(manager.jobCanceled),
	}
	if len(groupHandlers) > 0 {
		orbitalOpts = append(orbitalOpts,
			orbital.WithJobGroupDoneEventFunc(manager.jobGroupDone),
			orbital.WithJobGroupFailedEventFunc(manager.jobGroupFailed),
			orbital.WithJobGroupCanceledEventFunc(manager.jobGroupCanceled),
		)
	}

	orbitalManager, err := orbital.NewManager(repo, manager.resolveTasks, orbitalOpts...)
	if err != nil {
		return nil, errors.Join(err, closeTargets(ctx, targets))
	}

	// The config-derived default applies first so an explicit
	// WithMaxPendingReconciles option can override it.
	defaultMutator := func(m *orbital.Manager) {
		m.Config.MaxPendingReconciles = maxPendingReconciles(cfg.MaxReconcileCount)
	}
	for _, mutate := range append([]func(*orbital.Manager){defaultMutator}, options.orbitalMutators...) {
		mutate(orbitalManager)
	}
	manager.orbitalManager = orbitalManager

	return manager, nil
}

// addEmbeddedTarget registers the in-process embedded operator under the local
// target name. It fails if that name collides with a configured target.
func (m *Manager) addEmbeddedTarget(ctx context.Context, options builderOptions) error {
	if _, exists := m.targets[options.localTargetName]; exists {
		return errors.Join(
			fmt.Errorf("%w: %s", ErrLocalTargetDuplicate, options.localTargetName),
			closeTargets(ctx, m.targets),
		)
	}

	client, err := embedded.NewClient(
		buildTaskDispatch(m.taskHandlers),
		embedded.WithBufferSize(options.embeddedBufferSize),
		embedded.WithHandlerTimeout(options.embeddedHandlerTimeout),
	)
	if err != nil {
		return errors.Join(err, closeTargets(ctx, m.targets))
	}

	m.targets[options.localTargetName] = orbital.TargetManager{Client: client}
	return nil
}

func maxPendingReconciles(configured uint64) uint64 {
	if configured == 0 {
		return defaultMaxPendingReconciles
	}

	return configured
}

// LocalTarget returns the target name of the embedded operator. A task handler's
// ResolveTasks sets orbital.TaskInfo.Target to this value to run the task on root.
func (m *Manager) LocalTarget() string {
	return m.localTarget
}

func (m *Manager) Start(ctx context.Context) error {
	return m.orbitalManager.Start(ctx)
}

func (m *Manager) Stop(ctx context.Context) error {
	return errors.Join(m.orbitalManager.Stop(ctx), closeTargets(ctx, m.targets))
}

func (m *Manager) PrepareJob(ctx context.Context, job orbital.Job) (orbital.Job, error) {
	return m.orbitalManager.PrepareJob(ctx, job)
}

func (m *Manager) PrepareJobGroup(ctx context.Context, group orbital.JobGroup) (orbital.JobGroup, error) {
	return m.orbitalManager.PrepareJobGroup(ctx, group)
}

func (m *Manager) GetJob(ctx context.Context, jobID uuid.UUID) (orbital.Job, bool, error) {
	return m.orbitalManager.GetJob(ctx, jobID)
}

func (m *Manager) GetJobGroup(ctx context.Context, groupID uuid.UUID) (orbital.JobGroup, bool, error) {
	return m.orbitalManager.GetJobGroup(ctx, groupID)
}

func (m *Manager) ListTasks(ctx context.Context, query orbital.ListTasksQuery) ([]orbital.Task, error) {
	return m.orbitalManager.ListTasks(ctx, query)
}

func (m *Manager) CancelJob(ctx context.Context, jobID uuid.UUID) error {
	return m.orbitalManager.CancelJob(ctx, jobID)
}

func (m *Manager) CancelJobGroup(ctx context.Context, groupID uuid.UUID) error {
	return m.orbitalManager.CancelJobGroup(ctx, groupID)
}

func (m *Manager) confirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	handler, ok := m.jobHandlers[job.Type]
	if !ok {
		return orbital.CancelJobConfirmer(jobHandlerNotFoundError(job.Type).Error()), nil
	}

	return handler.ConfirmJob(ctx, job)
}

func (m *Manager) resolveTasks(ctx context.Context, job orbital.Job, cursor orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	handler, ok := m.jobHandlers[job.Type]
	if !ok {
		return orbital.CancelTaskResolver(jobHandlerNotFoundError(job.Type).Error()), nil
	}

	return handler.ResolveTasks(ctx, job, cursor)
}

func (m *Manager) jobDone(ctx context.Context, job orbital.Job) error {
	if handler, ok := m.jobHandlers[job.Type]; ok {
		return handler.OnJobDone(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func (m *Manager) jobFailed(ctx context.Context, job orbital.Job) error {
	if handler, ok := m.jobHandlers[job.Type]; ok {
		return handler.OnJobFailed(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func (m *Manager) jobCanceled(ctx context.Context, job orbital.Job) error {
	if handler, ok := m.jobHandlers[job.Type]; ok {
		return handler.OnJobCanceled(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func (m *Manager) jobGroupDone(ctx context.Context, group orbital.JobGroup) error {
	return m.dispatchGroupEvent(ctx, group, func(handler JobGroupHandler, resolved orbital.JobGroup) error {
		return handler.OnJobGroupDone(ctx, resolved)
	})
}

func (m *Manager) jobGroupFailed(ctx context.Context, group orbital.JobGroup) error {
	return m.dispatchGroupEvent(ctx, group, func(handler JobGroupHandler, resolved orbital.JobGroup) error {
		return handler.OnJobGroupFailed(ctx, resolved)
	})
}

func (m *Manager) jobGroupCanceled(ctx context.Context, group orbital.JobGroup) error {
	return m.dispatchGroupEvent(ctx, group, func(handler JobGroupHandler, resolved orbital.JobGroup) error {
		return handler.OnJobGroupCanceled(ctx, resolved)
	})
}

// dispatchGroupEvent refetches the group (orbital's event callback omits the
// Jobs slice) and hands it to the registered handler. An unregistered group
// type is a no-op.
func (m *Manager) dispatchGroupEvent(ctx context.Context, group orbital.JobGroup, fn func(JobGroupHandler, orbital.JobGroup) error) error {
	handler, ok := m.groupHandlers[group.Type]
	if !ok {
		return nil
	}

	resolved := group
	if refetched, found, err := m.orbitalManager.GetJobGroup(ctx, group.ID); err != nil {
		return err
	} else if found {
		resolved = refetched
	}

	return fn(handler, resolved)
}

func jobHandlerNotFoundError(jobType string) error {
	return fmt.Errorf("%w: %s", ErrJobHandlerNotFound, jobType)
}

func buildJobHandlerMap(handlers []JobHandler) (map[string]JobHandler, error) {
	if len(handlers) == 0 {
		return nil, ErrJobHandlerRequired
	}

	result := make(map[string]JobHandler, len(handlers))
	for _, handler := range handlers {
		if handler == nil {
			return nil, ErrJobHandlerNil
		}

		jobType := handler.JobType()
		if jobType == "" {
			return nil, ErrJobTypeEmpty
		}

		if _, ok := result[jobType]; ok {
			return nil, fmt.Errorf("%w: %s", ErrJobHandlerDuplicate, jobType)
		}
		result[jobType] = handler
	}

	return result, nil
}

func buildTargets(ctx context.Context, targetConfigs []config.ReconcilerTarget, targetProvider TargetProvider) (map[string]orbital.TargetManager, error) {
	targets := make(map[string]orbital.TargetManager, len(targetConfigs))
	if len(targetConfigs) == 0 {
		return targets, nil
	}
	if targetProvider == nil {
		return nil, ErrTargetFactoryRequired
	}

	for _, targetConfig := range targetConfigs {
		client, err := targetProvider(ctx, targetConfig)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("create target %s client: %w", targetConfig.Name, err), closeTargets(ctx, targets))
		}
		if client == nil {
			return nil, errors.Join(fmt.Errorf("%w: %s", ErrTargetClientNil, targetConfig.Name), closeTargets(ctx, targets))
		}

		targets[targetConfig.Name] = orbital.TargetManager{Client: client}
	}

	return targets, nil
}

func closeTargets(ctx context.Context, targets map[string]orbital.TargetManager) error {
	var errs []error
	for name, target := range targets {
		if target.Client != nil {
			if err := target.Client.Close(ctx); err != nil {
				errs = append(errs, fmt.Errorf("target %s: %w", name, err))
			}
		}
	}

	return errors.Join(errs...)
}
