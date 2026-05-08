package keys

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

type Service struct {
	UnimplementedServiceServer

	keyStore store.Key
}

func NewService(keyStore store.Key) *Service {
	return &Service{keyStore: keyStore}
}

func (s *Service) AnnounceKey(ctx context.Context, req *AnnounceKeyRequest) (*AnnounceKeyResponse, error) {
	var parentID *string
	if req.GetParentId() != "" {
		p := req.GetParentId()
		parentID = &p
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

func (s *Service) GetKey(ctx context.Context, req *GetKeyRequest) (*GetKeyResponse, error) {
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
