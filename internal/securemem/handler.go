package securemem

import (
	"context"
	"log/slog"
	"runtime"
	"runtime/secret"
)

type (
	// Handler is a function that takes a context and a HandlerRequest
	// and returns an error.
	Handler func(ctx context.Context, req *HandlerRequest) error
	// HandlerRequest is a struct that contains a temporary vault and a
	// persistent vault.
	HandlerRequest struct {
		temporaryVault  *MemVault
		persistentVault *MemVault
	}
	// HandlerResponse is a struct that contains a vault.
	HandlerResponse struct {
		vault *MemVault
	}
)

// PersistentVault returns the persistent vault of the HandlerRequest.
// This vault is intended to be used for storing data that needs to
// persist across multiple handler executions, while the temporary vault
// is intended for storing data that only needs to persist for the duration
// of a single handler execution.
func (r *HandlerRequest) PersistentVault() *MemVault {
	return r.persistentVault
}

// TemporaryVault returns the temporary vault of the HandlerRequest.
// This vault is intended to be used for storing data that only needs
// to persist for the duration of a single handler execution, while
// the persistent vault is intended for storing data that needs to
// persist across multiple handler executions.
func (r *HandlerRequest) TemporaryVault() *MemVault {
	return r.temporaryVault
}

// MemVault returns the vault of the HandlerResponse.
// This vault is intended to be used for storing data that needs to
// persist after the handler execution, and it is marked as read-only
// after the handler execution.
func (r *HandlerResponse) MemVault() *MemVault {
	return r.vault
}

// newHandlerRequest creates a new HandlerRequest with a new temporary
// vault and a new persistent vault.
func newHandlerRequest() *HandlerRequest {
	return &HandlerRequest{
		temporaryVault:  NewMemVault(),
		persistentVault: NewMemVault(),
	}
}

// Run executes the given handler with a new HandlerRequest and returns a
// HandlerResponse or an error.
func Run(ctx context.Context, handler Handler) (*HandlerResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	req := newHandlerRequest()
	var resp *HandlerResponse

	defer func() {
		err := req.TemporaryVault().DestroyAll()
		if err != nil {
			slog.Error("failed to destroy temp vault", "error", err)
		}
		if resp == nil {
			err = req.PersistentVault().DestroyAll()
			if err != nil {
				slog.Error("failed to destroy persistent vault after handler", "error", err)
			}
		}

		// calling GC here to ensure that any vault data that is no longer referenced is
		// collected and finalized before we mark the persistent vault as read-only.
		// This is important because if there are any vault data that are still referenced,
		// they may not be finalized and thus not properly cleaned up, which could lead to
		// memory leaks or security issues.
		runtime.GC()
	}()

	var err error
	secret.Do(func() {
		err = handler(ctx, req)
	})

	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	persistentVault := req.PersistentVault()
	err = persistentVault.MarkAllReadOnly()
	if err != nil {
		return nil, err
	}

	resp = &HandlerResponse{vault: persistentVault}

	return resp, nil
}
