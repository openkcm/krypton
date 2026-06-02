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
	jobPreparer JobPreparer
}

func NewKeyService(keyStore store.Key, jobPreparer JobPreparer) *KeyService {
	return &KeyService{keyStore: keyStore, jobPreparer: jobPreparer}
}

// AnnounceKey is idempotent on (tenant_id, name).
//
// Flow:
//  1. Try CreateKey. If it succeeds, we own a fresh key.
//  2. If CreateKey returns ErrKeyAlreadyExists, fetch the existing key by
//     name. If it already has a JobID recorded in its processing state, we
//     return it as-is — the caller is retrying a previously successful
//     request, so we hand back the same identifiers.
//  3. Otherwise, prepare an orbital job using key.ID as ExternalID. Because
//     the ExternalID is deterministic across retries, orbital's
//     (external_id, type) unique index acts as a second line of defense
//     against duplicate jobs in concurrent retries.
//  4. Persist the job linkage (KeyProcessingState) so subsequent retries
//     short-circuit at step 2.
func (s *KeyService) AnnounceKey(ctx context.Context, req *AnnounceKeyRequest) (*AnnounceKeyResponse, error) {
	var parentID *string
	if pid := req.GetParentId(); pid != "" {
		parentID = &pid
	}

	newKey := model.NewKey(
		req.GetTenantId(),
		req.GetName(),
		req.GetKind(),
		parentID,
		req.GetTargetName(),
		req.GetLabels(),
	)

	key, err := s.upsertKey(ctx, newKey)
	if err != nil {
		return nil, err
	}

	// If a job is already linked, the caller is retrying — return as-is.
	if key.KeyProcessingState.JobID != "" {
		return &AnnounceKeyResponse{Key: KeyToProto(key)}, nil
	}

	taskData := announcekey.TaskData{
		KeyID:    key.ID,
		TenantID: key.TenantID,
		Kind:     string(key.Kind),
		Name:     key.Name,
		ParentID: req.GetParentId(),
		Target:   req.GetTargetName(),
		Labels:   req.GetLabels(),
	}

	data, err := json.Marshal(taskData)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to marshal job data"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	job := orbital.NewJob(announcekey.JobType, data).WithExternalID(key.ID)
	prepared, prepErr := s.jobPreparer.PrepareJob(ctx, job)
	switch {
	case prepErr == nil:
		key.KeyProcessingState = model.KeyProcessingState{
			Status: model.KeyProcessingInProgress,
			JobID:  prepared.ID.String(),
		}
		if err := s.keyStore.UpdateKeyProcessingState(ctx, store.UpdateKeyProcessingStateQuery{
			ID:        key.ID,
			TenantID:  key.TenantID,
			NewStatus: model.KeyProcessingInProgress,
			NewJobID:  prepared.ID.String(),
		}); err != nil {
			// The job is on the way — log but don't fail the request, the
			// JobHandler's lifecycle hooks will re-write processing state
			// when the job terminates.
			slogctx.Warn(ctx, "failed to record job linkage on key", "err", err, "keyID", key.ID)
		}
	case errors.Is(prepErr, orbital.ErrJobAlreadyExists):
		// Concurrent racer beat us to PrepareJob with the same ExternalID.
		// Orbital deduped the job; the winner will (or already did) record
		// the JobID on the key. Return what we have — the next GetKey call
		// will reflect the linkage once the winner finishes its
		// UpdateKeyProcessingState.
		slogctx.Info(ctx, "announce-key job already exists for this ExternalID, returning existing key", "keyID", key.ID)
	default:
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to prepare announce key job"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &AnnounceKeyResponse{Key: KeyToProto(key)}, nil
}

// upsertKey returns the persisted Key, either freshly inserted or read back
// after a unique-constraint conflict. It only returns a gRPC error.
func (s *KeyService) upsertKey(ctx context.Context, newKey model.Key) (model.Key, error) {
	err := s.keyStore.CreateKey(ctx, newKey)
	switch {
	case err == nil:
		return newKey, nil
	case errors.Is(err, store.ErrKeyAlreadyExists):
		existing, lookupErr := s.keyStore.GetKeyByName(ctx, store.GetKeyByNameQuery{
			TenantID: newKey.TenantID,
			Name:     newKey.Name,
		})
		if lookupErr != nil {
			return model.Key{}, proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to look up existing key"),
				proto.Code_ERROR_CODE_RETRY,
			)
		}
		return *existing, nil
	default:
		return model.Key{}, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to announce key"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
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
		KeyTree: KeyTreeToProto(res.KeyTree),
	}, nil
}
