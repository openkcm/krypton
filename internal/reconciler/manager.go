package reconciler

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"

	"github.com/openkcm/krypton/internal/config"
)

const (
	noJobHandlerRegisteredMessage        = "no job handler registered for job type"
	defaultMaxPendingReconciles   uint64 = 10
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

type TargetProvider func(context.Context, config.ReconcilerTarget) (orbital.Initiator, error)

// Manager owns the Orbital manager lifecycle for a Krypton process.
type Manager struct {
	orbitalManager *orbital.Manager
	handlers       map[string]JobHandler
	targets        map[string]orbital.TargetManager
}

// NewManager wires handlers, target clients, and Orbital worker config.
func NewManager(
	ctx context.Context,
	cfg *config.ReconcilerConfig,
	repo *orbital.Repository,
	targetProvider TargetProvider,
	handlers []JobHandler,
	options ...Option,
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

	handlerMap, err := buildHandlerMap(handlers)
	if err != nil {
		return nil, err
	}

	targets, err := buildTargets(ctx, cfg.Targets, targetProvider)
	if err != nil {
		return nil, err
	}

	manager := &Manager{handlers: handlerMap, targets: targets}
	orbitalManager, err := orbital.NewManager(
		repo,
		manager.resolveTasks,
		orbital.WithTargets(targets),
		orbital.WithJobConfirmFunc(manager.confirmJob),
		orbital.WithJobDoneEventFunc(manager.jobDone),
		orbital.WithJobFailedEventFunc(manager.jobFailed),
		orbital.WithJobCanceledEventFunc(manager.jobCanceled),
	)
	if err != nil {
		return nil, errors.Join(err, closeTargets(ctx, targets))
	}

	WithMaxPendingReconciles(maxPendingReconciles(cfg.MaxReconcileCount))(orbitalManager)
	for _, option := range options {
		option(orbitalManager)
	}
	manager.orbitalManager = orbitalManager

	return manager, nil
}

func maxPendingReconciles(configured uint64) uint64 {
	if configured == 0 {
		return defaultMaxPendingReconciles
	}

	return configured
}

func (m *Manager) PrepareJob(ctx context.Context, job orbital.Job) (orbital.Job, error) {
	return m.orbitalManager.PrepareJob(ctx, job)
}

func (m *Manager) Start(ctx context.Context) error {
	return m.orbitalManager.Start(ctx)
}

func (m *Manager) Stop(ctx context.Context) error {
	return errors.Join(m.orbitalManager.Stop(ctx), closeTargets(ctx, m.targets))
}

func (m *Manager) confirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	handler, ok := m.handlers[job.Type]
	if !ok {
		return orbital.CancelJobConfirmer(jobHandlerNotFoundError(job.Type).Error()), nil
	}

	return handler.ConfirmJob(ctx, job)
}

func (m *Manager) resolveTasks(ctx context.Context, job orbital.Job, cursor orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	handler, ok := m.handlers[job.Type]
	if !ok {
		return orbital.CancelTaskResolver(jobHandlerNotFoundError(job.Type).Error()), nil
	}

	return handler.ResolveTasks(ctx, job, cursor)
}

func (m *Manager) jobDone(ctx context.Context, job orbital.Job) error {
	if handler, ok := m.handlers[job.Type]; ok {
		return handler.OnJobDone(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func (m *Manager) jobFailed(ctx context.Context, job orbital.Job) error {
	if handler, ok := m.handlers[job.Type]; ok {
		return handler.OnJobFailed(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func (m *Manager) jobCanceled(ctx context.Context, job orbital.Job) error {
	if handler, ok := m.handlers[job.Type]; ok {
		return handler.OnJobCanceled(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func jobHandlerNotFoundError(jobType string) error {
	return fmt.Errorf("%w: %s", ErrJobHandlerNotFound, jobType)
}

func buildHandlerMap(handlers []JobHandler) (map[string]JobHandler, error) {
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
