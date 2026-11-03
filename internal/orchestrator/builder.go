package orchestrator

import (
	"context"
	"errors"
	"fmt"

	"github.com/openkcm/orbital"
)

const (
	// DefaultLocalTargetName is the target name under which the embedded
	// operator is registered when no name is set with WithLocalTargetName.
	DefaultLocalTargetName = "krypton-embedded"

	defaultEmbeddedBufferSize      = 10
	noTaskHandlerRegisteredMessage = "no task handler registered for task type"
)

var (
	ErrTaskHandlerRequired  = errors.New("at least one task handler is required")
	ErrTaskHandlerNil       = errors.New("task handler cannot be nil")
	ErrTaskTypeEmpty        = errors.New("task handler type cannot be empty")
	ErrTaskHandlerDuplicate = errors.New("duplicate task handler")

	ErrJobHandlerRequired  = errors.New("at least one job handler is required")
	ErrJobHandlerNil       = errors.New("job handler cannot be nil")
	ErrJobTypeEmpty        = errors.New("job handler type cannot be empty")
	ErrJobHandlerDuplicate = errors.New("duplicate job handler")

	ErrGroupHandlerNil       = errors.New("job group handler cannot be nil")
	ErrGroupTypeEmpty        = errors.New("job group handler type cannot be empty")
	ErrGroupHandlerDuplicate = errors.New("duplicate job group handler")
)

// buildTaskDispatch returns a single orbital.HandlerFunc that routes each task
// request to the handler registered for its task type. An unregistered task
// type fails the task rather than silently succeeding.
func buildTaskDispatch(handlers map[string]OrbitalTaskHandler) orbital.HandlerFunc {
	return func(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
		handler, ok := handlers[req.TaskType]
		if !ok {
			resp.Fail(fmt.Sprintf("%s: %s", noTaskHandlerRegisteredMessage, req.TaskType))
			return
		}

		handler.Handle(ctx, req, resp)
	}
}

func buildTaskHandlerMap(handlers []OrbitalTaskHandler) (map[string]OrbitalTaskHandler, error) {
	if len(handlers) == 0 {
		return nil, ErrTaskHandlerRequired
	}

	result := make(map[string]OrbitalTaskHandler, len(handlers))
	for _, handler := range handlers {
		if handler == nil {
			return nil, ErrTaskHandlerNil
		}

		taskType := handler.TaskType()
		if taskType == "" {
			return nil, ErrTaskTypeEmpty
		}

		if _, ok := result[taskType]; ok {
			return nil, fmt.Errorf("%w: %s", ErrTaskHandlerDuplicate, taskType)
		}
		result[taskType] = handler
	}

	return result, nil
}

func buildTaskResolverMap(handlers []OrbitalTaskResolver) (map[string]OrbitalTaskResolver, error) {
	if len(handlers) == 0 {
		return nil, ErrJobHandlerRequired
	}

	result := make(map[string]OrbitalTaskResolver, len(handlers))
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

func buildGroupHandlerMap(handlers []OrbitalJobGroupHandler) (map[string]OrbitalJobGroupHandler, error) {
	result := make(map[string]OrbitalJobGroupHandler, len(handlers))
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
