package admin

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/reconciler/handler/announcekey"
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

func (s *KeyService) AnnounceKey(ctx context.Context, req *AnnounceKeyRequest) (*AnnounceKeyResponse, error) {
	var parentID *string
	if req.GetParentId() != "" {
		parentID = new(req.GetParentId())
	}

	key := model.NewKey(
		req.GetTenantId(),
		req.GetName(),
		req.GetKind(),
		parentID,
		req.GetTargetName(),
		req.GetLabels(),
	)

	if err := s.keyStore.CreateKey(ctx, key); err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to announce key"),
			proto.Code_ERROR_CODE_RETRY,
		)
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
	if _, err := s.jobPreparer.PrepareJob(ctx, job); err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to prepare announce key job"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &AnnounceKeyResponse{Key: KeyToProto(key)}, nil
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
