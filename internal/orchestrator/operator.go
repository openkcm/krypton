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
)

// buildTaskDispatch returns a single orbital.HandlerFunc that routes each task
// request to the handler registered for its task type. An unregistered task
// type fails the task rather than silently succeeding.
func buildTaskDispatch(handlers map[string]TaskHandler) orbital.HandlerFunc {
	return func(ctx context.Context, req orbital.HandlerRequest, resp *orbital.HandlerResponse) {
		handler, ok := handlers[req.TaskType]
		if !ok {
			resp.Fail(fmt.Sprintf("%s: %s", noTaskHandlerRegisteredMessage, req.TaskType))
			return
		}

		handler.Handle(ctx, req, resp)
	}
}

func buildTaskHandlerMap(handlers []TaskHandler) (map[string]TaskHandler, error) {
	if len(handlers) == 0 {
		return nil, ErrTaskHandlerRequired
	}

	result := make(map[string]TaskHandler, len(handlers))
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
