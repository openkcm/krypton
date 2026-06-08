package admin

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	slogctx "github.com/veqryn/slog-context"

	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type JobPreparer interface {
	PrepareJob(ctx context.Context, job orbital.Job) (orbital.Job, error)
}

type KeyService struct {
	UnimplementedKeyServiceServer

	keyStore    store.Key
	tenantStore store.Tenant
	hierarchy   spec.KeyHierarchy
	jobPreparer JobPreparer
}

func NewKeyService(keyStore store.Key, tenantStore store.Tenant, hierarchy spec.KeyHierarchy, jobPreparer JobPreparer) *KeyService {
	return &KeyService{
		keyStore:    keyStore,
		tenantStore: tenantStore,
		hierarchy:   hierarchy,
		jobPreparer: jobPreparer,
	}
}

// AnnounceKey validates the request, prepares an orbital job first, and then
// commits the key to local storage with the resulting JobID baked in.
//
// The "job-first, then key" ordering is the orbital double-commit pattern:
// if the process crashes between PrepareJob and CreateKey, the orbital job
// has no domain-state counterpart and ConfirmJob cancels it cleanly.
//
// Idempotency is keyed on (tenant_id, name):
//   - In-progress / completed announces short-circuit and return the existing key.
//   - Failed announces re-prepare a new orbital job (with a retry-scoped
//     ExternalID) for the same key and reset the linkage to in-progress.
func (s *KeyService) AnnounceKey(ctx context.Context, req *AnnounceKeyRequest) (*AnnounceKeyResponse, error) {
	keySpec, vErr := s.validateAnnounceRequest(ctx, req)
	if vErr != nil {
		return nil, vErr
	}

	existing, lookupErr := s.keyStore.GetKeyByName(ctx, store.GetKeyByNameQuery{
		TenantID: req.GetTenantId(),
		Name:     req.GetName(),
	})
	switch {
	case lookupErr == nil:
		switch existing.KeyProcessingState.Status {
		case model.KeyProcessingInProgress, model.KeyProcessingCompleted:
			return &AnnounceKeyResponse{Key: KeyToProto(*existing)}, nil
		default:
			// Pending (interrupted before PrepareJob) or Failed (terminal-failed
			// retry) — re-link a fresh orbital job to the existing key.
			return s.prepareAndLink(ctx, *existing)
		}
	case errors.Is(lookupErr, store.ErrKeyNotFound):
		var parentID *string
		if pid := req.GetParentId(); pid != "" {
			parentID = &pid
		}
		newKey := model.NewKey(
			req.GetTenantId(),
			req.GetName(),
			string(keySpec.Kind),
			parentID,
			req.GetTargetName(),
			req.GetLabels(),
		)
		return s.prepareAndCreate(ctx, newKey)
	default:
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to look up existing key"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
}

// validateAnnounceRequest enforces tenant existence, hierarchy membership of
// Kind, root-vs-parent shape, and parent's lifecycle/adjacency. Returns the
// resolved KeySpec on success or a gRPC error on failure.
func (s *KeyService) validateAnnounceRequest(ctx context.Context, req *AnnounceKeyRequest) (spec.KeySpec, error) {
	if _, err := s.tenantStore.GetTenant(ctx, store.GetTenantQuery{ID: req.GetTenantId()}); err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			return spec.KeySpec{}, proto.ErrDetailsWithCode(
				status.New(codes.FailedPrecondition, "tenant not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return spec.KeySpec{}, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to look up tenant"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	keySpec, ok := s.hierarchy.FindKeySpec(model.KeyKind(req.GetKind()))
	if !ok {
		return spec.KeySpec{}, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, "kind not in hierarchy"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	parentIDStr := req.GetParentId()
	if parentIDStr == "" {
		if keySpec.Role != spec.KeyRoleRoot {
			return spec.KeySpec{}, proto.ErrDetailsWithCode(
				status.New(codes.InvalidArgument, "non-root kind requires a parent"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return keySpec, nil
	}

	if keySpec.Role == spec.KeyRoleRoot {
		return spec.KeySpec{}, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, "root kind cannot have a parent"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	parent, err := s.keyStore.GetKeyByID(ctx, parentIDStr, req.GetTenantId())
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return spec.KeySpec{}, proto.ErrDetailsWithCode(
				status.New(codes.FailedPrecondition, "parent key not found in tenant"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return spec.KeySpec{}, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to look up parent key"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	if parent.LifeCycleState != model.KeyLifeCycleActive {
		return spec.KeySpec{}, proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, "parent key is not active"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	// Strict adjacency: child must sit immediately below parent in the hierarchy.
	if s.hierarchy.IndexOf(parent.Kind)+1 != s.hierarchy.IndexOf(keySpec.Kind) {
		return spec.KeySpec{}, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, "kind cannot be attached to parent's kind in hierarchy"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return keySpec, nil
}

// prepareAndCreate runs PrepareJob first, then commits a brand-new key with
// the JobID baked into KeyProcessingState.
func (s *KeyService) prepareAndCreate(ctx context.Context, key model.Key) (*AnnounceKeyResponse, error) {
	prepared, err := s.prepareJob(ctx, key, key.ID)
	if err != nil {
		if errors.Is(err, orbital.ErrJobAlreadyExists) {
			return s.fetchByName(ctx, key.TenantID, key.Name, "failed to look up existing key after job dedup")
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to prepare announce key job"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	key.KeyProcessingState = model.KeyProcessingState{
		Status: model.KeyProcessingInProgress,
		JobID:  prepared.ID.String(),
	}

	if err := s.keyStore.CreateKey(ctx, key); err != nil {
		if errors.Is(err, store.ErrKeyAlreadyExists) {
			// A concurrent racer created a key with the same (tenant, name)
			// between our GetKeyByName and CreateKey. Our orbital job will be
			// cancelled by ConfirmJob when it can't find a key with our key.ID.
			return s.fetchByName(ctx, key.TenantID, key.Name, "failed to look up existing key after create race")
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to create key"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &AnnounceKeyResponse{Key: KeyToProto(key)}, nil
}

// prepareAndLink prepares a fresh orbital job for an existing key (failed
// retry or pending re-attempt) and updates its processing state to
// in-progress with the new JobID.
func (s *KeyService) prepareAndLink(ctx context.Context, key model.Key) (*AnnounceKeyResponse, error) {
	externalID := key.ID
	if key.KeyProcessingState.Status == model.KeyProcessingFailed && key.KeyProcessingState.JobID != "" {
		// Distinct ExternalID per failed attempt so orbital doesn't dedupe
		// against the prior terminal job, while concurrent retry callers
		// (same prior failed JobID) still collide on this ID.
		externalID = key.ID + ":retry:" + key.KeyProcessingState.JobID
	}

	prepared, err := s.prepareJob(ctx, key, externalID)
	if err != nil {
		if errors.Is(err, orbital.ErrJobAlreadyExists) {
			// Concurrent retry won the race; surface the existing key as-is.
			return &AnnounceKeyResponse{Key: KeyToProto(key)}, nil
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to prepare announce key job"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	if err := s.keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
		ID:        key.ID,
		TenantID:  key.TenantID,
		NewStatus: model.KeyProcessingInProgress,
		NewJobID:  prepared.ID.String(),
	}); err != nil {
		// The job is on the way — log and let the lifecycle hooks rewrite
		// processing state when the job terminates.
		slogctx.Warn(ctx, "failed to record job linkage on key", "err", err, "keyID", key.ID)
	}

	key.KeyProcessingState = model.KeyProcessingState{
		Status: model.KeyProcessingInProgress,
		JobID:  prepared.ID.String(),
	}
	return &AnnounceKeyResponse{Key: KeyToProto(key)}, nil
}

func (s *KeyService) prepareJob(ctx context.Context, key model.Key, externalID string) (orbital.Job, error) {
	taskData := announcekey.TaskData{
		KeyID:    key.ID,
		TenantID: key.TenantID,
		Kind:     string(key.Kind),
		Name:     key.Name,
		Target:   key.ManagedBy,
		Labels:   map[string]string(key.Labels),
	}
	if key.ParentID != nil {
		taskData.ParentID = *key.ParentID
	}

	data, err := json.Marshal(taskData)
	if err != nil {
		return orbital.Job{}, err
	}

	job := orbital.NewJob(announcekey.JobType, data).WithExternalID(externalID)
	return s.jobPreparer.PrepareJob(ctx, job)
}

func (s *KeyService) fetchByName(ctx context.Context, tenantID, name, failureMsg string) (*AnnounceKeyResponse, error) {
	existing, err := s.keyStore.GetKeyByName(ctx, store.GetKeyByNameQuery{
		TenantID: tenantID,
		Name:     name,
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, failureMsg),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
	return &AnnounceKeyResponse{Key: KeyToProto(*existing)}, nil
}

func (s *KeyService) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
	key, err := s.keyStore.GetKeyByID(ctx, req.GetId(), req.GetTenantId())
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "key not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get key"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &GetKeyResponse{Key: KeyToProto(*key)}, nil
}

func (s *KeyService) GetParentKeys(ctx context.Context, req *GetParentKeysRequest) (*GetParentKeysResponse, error) {
	res, err := s.keyStore.GetParentKeys(ctx, store.GetParentKeysQuery{
		KeyID:    req.GetId(),
		TenantID: req.GetTenantId(),
	})
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "key not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get parent keys"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &GetParentKeysResponse{
		Keys: KeysToProto(res.Keys),
	}, nil
}

func (s *KeyService) GetDescendantKeys(ctx context.Context, req *GetDescendantKeysRequest) (*GetDescendantKeysResponse, error) {
	res, err := s.keyStore.GetDescendantKeys(ctx, store.GetDescendantKeysQuery{
		KeyID:    req.GetId(),
		TenantID: req.GetTenantId(),
	})
	if err != nil {
		if errors.Is(err, store.ErrKeyNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "key not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get descendant keys"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &GetDescendantKeysResponse{
		KeyTree: KeyTreeTraverserToProto(res.KeyTree),
	}, nil
}
