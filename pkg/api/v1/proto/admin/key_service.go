package admin

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type KeyService struct {
	UnimplementedKeyServiceServer

	keyStore store.Key
}

func NewKeyService(keyStore store.Key) *KeyService {
	return &KeyService{keyStore: keyStore}
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
			status.New(codes.Internal, "failed to get key chain"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &GetParentKeysResponse{
		Keys: KeysToProto(res.Keys),
	}, nil
}
