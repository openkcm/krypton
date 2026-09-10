package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"time"
	"uuid"

	"github.com/openkcm/orbital"
	"github.com/openkcm/orbital/client/embedded"
)

const (
	noJobHandlerRegisteredMessage        = "no job handler registered for job type"
	defaultMaxPendingReconciles   uint64 = 10
	defaultEmbeddedHandlerTimeout        = 90 * time.Second
)

var (
	ErrRepositoryNil       = errors.New("orbital repository cannot be nil")
	ErrJobHandlerRequired  = errors.New("at least one job handler is required")
	ErrJobHandlerNil       = errors.New("job handler cannot be nil")
	ErrJobTypeEmpty        = errors.New("job handler type cannot be empty")
	ErrJobHandlerDuplicate = errors.New("duplicate job handler")
	ErrJobHandlerNotFound  = errors.New(noJobHandlerRegisteredMessage)

	ErrGroupHandlerNil       = errors.New("job group handler cannot be nil")
	ErrGroupTypeEmpty        = errors.New("job group handler type cannot be empty")
	ErrGroupHandlerDuplicate = errors.New("duplicate job group handler")
)

// Orchestrator owns the orbital manager lifecycle plus the embedded operator for
// a Krypton process. It routes orbital's job, job-group, and task callbacks to
// the registered handlers.
type Orchestrator struct {
	repo           *orbital.Repository
	orbitalManager *orbital.Manager
	jobHandlers    map[string]JobHandler
	groupHandlers  map[string]JobGroupHandler
	taskHandlers   map[string]TaskHandler
	targets        map[string]orbital.TargetManager
	localTarget    string

	embeddedBufferSize     int
	embeddedHandlerTimeout time.Duration
	orbitalMutators        []func(*orbital.Manager)
}

// New wires the registered handlers, the embedded operator (only when at least
// one task handler is registered), and orbital worker config.
func New(ctx context.Context, repo *orbital.Repository, handlers Handlers, opts ...Option) (*Orchestrator, error) {
	if repo == nil {
		return nil, ErrRepositoryNil
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

	o := &Orchestrator{
		repo:                   repo,
		jobHandlers:            jobHandlers,
		groupHandlers:          groupHandlers,
		taskHandlers:           taskHandlers,
		targets:                make(map[string]orbital.TargetManager),
		localTarget:            DefaultLocalTargetName,
		embeddedBufferSize:     defaultEmbeddedBufferSize,
		embeddedHandlerTimeout: defaultEmbeddedHandlerTimeout,
	}
	for _, opt := range opts {
		opt(o)
	}

	if len(taskHandlers) > 0 {
		if err := o.addEmbeddedTarget(); err != nil {
			return nil, err
		}
	}

	orbitalOpts := []orbital.ManagerOptsFunc{
		orbital.WithTargets(o.targets),
		orbital.WithJobConfirmFunc(o.confirmJob),
		orbital.WithJobDoneEventFunc(o.jobDone),
		orbital.WithJobFailedEventFunc(o.jobFailed),
		orbital.WithJobCanceledEventFunc(o.jobCanceled),
	}
	if len(groupHandlers) > 0 {
		orbitalOpts = append(orbitalOpts,
			orbital.WithJobGroupDoneEventFunc(o.jobGroupDone),
			orbital.WithJobGroupFailedEventFunc(o.jobGroupFailed),
			orbital.WithJobGroupCanceledEventFunc(o.jobGroupCanceled),
		)
	}

	orbitalManager, err := orbital.NewManager(repo, o.resolveTasks, orbitalOpts...)
	if err != nil {
		return nil, errors.Join(err, closeTargets(ctx, o.targets))
	}

	// Apply the default first so WithMaxPendingReconciles can override it.
	orbitalManager.Config.MaxPendingReconciles = defaultMaxPendingReconciles
	for _, mutate := range o.orbitalMutators {
		mutate(orbitalManager)
	}
	o.orbitalManager = orbitalManager

	return o, nil
}

// addEmbeddedTarget registers the in-process embedded operator under the local
// target name.
func (o *Orchestrator) addEmbeddedTarget() error {
	client, err := embedded.NewClient(
		buildTaskDispatch(o.taskHandlers),
		embedded.WithBufferSize(o.embeddedBufferSize),
		embedded.WithHandlerTimeout(o.embeddedHandlerTimeout),
	)
	if err != nil {
		return err
	}

	o.targets[o.localTarget] = orbital.TargetManager{Client: client}
	return nil
}

// LocalTarget returns the target name of the embedded operator. A task handler's
// ResolveTasks sets orbital.TaskInfo.Target to this value to run the task on root.
func (o *Orchestrator) LocalTarget() string {
	return o.localTarget
}

func (o *Orchestrator) Start(ctx context.Context) error {
	return o.orbitalManager.Start(ctx)
}

func (o *Orchestrator) Stop(ctx context.Context) error {
	return errors.Join(o.orbitalManager.Stop(ctx), closeTargets(ctx, o.targets))
}

func (o *Orchestrator) PrepareJob(ctx context.Context, job orbital.Job) (orbital.Job, error) {
	return o.orbitalManager.PrepareJob(ctx, job)
}

func (o *Orchestrator) PrepareJobGroup(ctx context.Context, group orbital.JobGroup) (orbital.JobGroup, error) {
	return o.orbitalManager.PrepareJobGroup(ctx, group)
}

func (o *Orchestrator) GetJob(ctx context.Context, jobID uuid.UUID) (orbital.Job, bool, error) {
	return o.orbitalManager.GetJob(ctx, jobID)
}

func (o *Orchestrator) GetJobGroup(ctx context.Context, groupID uuid.UUID) (orbital.JobGroup, bool, error) {
	return o.orbitalManager.GetJobGroup(ctx, groupID)
}

func (o *Orchestrator) ListTasks(ctx context.Context, query orbital.ListTasksQuery) ([]orbital.Task, error) {
	return o.orbitalManager.ListTasks(ctx, query)
}

func (o *Orchestrator) CancelJob(ctx context.Context, jobID uuid.UUID) error {
	return o.orbitalManager.CancelJob(ctx, jobID)
}

func (o *Orchestrator) CancelJobGroup(ctx context.Context, groupID uuid.UUID) error {
	return o.orbitalManager.CancelJobGroup(ctx, groupID)
}

func (o *Orchestrator) confirmJob(ctx context.Context, job orbital.Job) (orbital.JobConfirmerResult, error) {
	handler, ok := o.jobHandlers[job.Type]
	if !ok {
		return orbital.CancelJobConfirmer(jobHandlerNotFoundError(job.Type).Error()), nil
	}

	return handler.ConfirmJob(ctx, job)
}

func (o *Orchestrator) resolveTasks(ctx context.Context, job orbital.Job, cursor orbital.TaskResolverCursor) (orbital.TaskResolverResult, error) {
	handler, ok := o.jobHandlers[job.Type]
	if !ok {
		return orbital.CancelTaskResolver(jobHandlerNotFoundError(job.Type).Error()), nil
	}

	return handler.ResolveTasks(ctx, job, cursor)
}

func (o *Orchestrator) jobDone(ctx context.Context, job orbital.Job) error {
	if handler, ok := o.jobHandlers[job.Type]; ok {
		return handler.OnJobDone(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func (o *Orchestrator) jobFailed(ctx context.Context, job orbital.Job) error {
	if handler, ok := o.jobHandlers[job.Type]; ok {
		return handler.OnJobFailed(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func (o *Orchestrator) jobCanceled(ctx context.Context, job orbital.Job) error {
	if handler, ok := o.jobHandlers[job.Type]; ok {
		return handler.OnJobCanceled(ctx, job)
	}

	return jobHandlerNotFoundError(job.Type)
}

func (o *Orchestrator) jobGroupDone(ctx context.Context, group orbital.JobGroup) error {
	return o.dispatchGroupEvent(ctx, group, func(handler JobGroupHandler, resolved orbital.JobGroup) error {
		return handler.OnJobGroupDone(ctx, resolved)
	})
}

func (o *Orchestrator) jobGroupFailed(ctx context.Context, group orbital.JobGroup) error {
	return o.dispatchGroupEvent(ctx, group, func(handler JobGroupHandler, resolved orbital.JobGroup) error {
		return handler.OnJobGroupFailed(ctx, resolved)
	})
}

func (o *Orchestrator) jobGroupCanceled(ctx context.Context, group orbital.JobGroup) error {
	return o.dispatchGroupEvent(ctx, group, func(handler JobGroupHandler, resolved orbital.JobGroup) error {
		return handler.OnJobGroupCanceled(ctx, resolved)
	})
}

// dispatchGroupEvent refetches the group (orbital's event callback omits the
// Jobs slice) and hands it to the registered handler. An unregistered group
// type is a no-op.
func (o *Orchestrator) dispatchGroupEvent(ctx context.Context, group orbital.JobGroup, fn func(JobGroupHandler, orbital.JobGroup) error) error {
	handler, ok := o.groupHandlers[group.Type]
	if !ok {
		return nil
	}

	resolved := group
	if refetched, found, err := o.orbitalManager.GetJobGroup(ctx, group.ID); err != nil {
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

func buildGroupHandlerMap(handlers []JobGroupHandler) (map[string]JobGroupHandler, error) {
	result := make(map[string]JobGroupHandler, len(handlers))
	for _, handler := range handlers {
		if handler == nil {
			return nil, ErrGroupHandlerNil
		}

		groupType := handler.JobGroupType()
		if groupType == "" {
			return nil, ErrGroupTypeEmpty
		}

		if _, ok := result[groupType]; ok {
			return nil, fmt.Errorf("%w: %s", ErrGroupHandlerDuplicate, groupType)
		}
		result[groupType] = handler
	}

	return result, nil
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
