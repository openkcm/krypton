package example

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/openkcm/orbital"
	"github.com/openkcm/orbital/client/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/orchestrator"
)

// KeySpec describes one key in a hierarchy to activate. The order of a
// []KeySpec is the cascade order: a key's parent must appear before it.
type KeySpec struct {
	// ID is the key identifier.
	ID string
	// ParentID is the parent key that must be active first; empty for the root.
	ParentID string
	// Target is the operator that owns this key — the manager's LocalTarget for
	// root-managed keys, or a configured agent target name for delegated keys.
	Target string
}

// Setup wires the three example handlers into an orchestrator.Manager, exactly
// as cmd/root would wire a real operation. Because a task handler is
// registered, the manager lazily stands up the in-process embedded operator;
// its LocalTarget is what root-managed KeySpecs should target.
//
// store stands in for the root's key store (used by the job handler) and, in
// this single-process example, for every operator's local store (used by the
// task handler). A real deployment would give each its own.
func Setup(
	ctx context.Context,
	cfg *config.ReconcilerConfig,
	repo *orbital.Repository,
	store *KeyStore,
	log *slog.Logger,
) (*orchestrator.Manager, error) {
	handlers := orchestrator.Handlers{
		Jobs:   []orchestrator.JobHandler{NewActivateKeyJobHandler(store, log)},
		Groups: []orchestrator.JobGroupHandler{NewCascadeGroupHandler(log)},
		Tasks:  []orchestrator.TaskHandler{NewActivateKeyTaskHandler(store, log)},
	}

	opts := []orchestrator.Option{}
	if len(cfg.Targets) > 0 {
		// Only needed when the config lists remote agent operators.
		opts = append(opts, orchestrator.WithTargetProvider(dialAgent))
	}
	if cfg.ExecInterval > 0 {
		opts = append(opts, orchestrator.WithExecInterval(cfg.ExecInterval))
	}

	return orchestrator.NewManager(ctx, cfg, repo, handlers, opts...)
}

// dialAgent dials a configured agent operator over gRPC and wraps it in an
// orbital rpc client. This mirrors cmd/root's target provider.
func dialAgent(_ context.Context, target config.ReconcilerTarget) (orbital.Initiator, error) {
	conn, err := grpc.NewClient(target.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return rpc.NewClient(conn)
}

// NewCascade builds the job group that activates the given hierarchy. Callers
// hand the returned group to Manager.PrepareJobGroup to start the cascade; the
// group handler's OnJobGroupDone fires once every activation completes.
func NewCascade(keys []KeySpec) (orbital.JobGroup, error) {
	jobs := make([]orbital.Job, 0, len(keys))
	for _, key := range keys {
		data, err := json.Marshal(ActivateKeyData{
			KeyID:    key.ID,
			ParentID: key.ParentID,
			Target:   key.Target,
		})
		if err != nil {
			return orbital.JobGroup{}, err
		}

		// Labels are namespaced "krypton/…"; the "orbital/" prefix is reserved.
		job := orbital.NewJob(JobTypeActivateKey, data).
			WithExternalID(key.ID).
			WithLabels(orbital.Labels{"krypton/key": key.ID})
		jobs = append(jobs, job)
	}

	return orbital.NewJobGroup(GroupTypeCascade, jobs...), nil
}
