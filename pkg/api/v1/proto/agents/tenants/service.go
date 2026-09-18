package tenants

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

type Service struct {
	UnimplementedTenantServiceServer

	transactor store.Transactor
}

func NewTenantService(t store.Transactor) *Service {
	return &Service{
		transactor: t,
	}
}

func (s *Service) UpsertTenant(ctx context.Context, req *UpsertTenantRequest) (*UpsertTenantResponse, error) {
	err := validator.ValidateUpsertTenant(validator.UpsertTenantInput{
		ID:   req.GetId(),
		Name: req.GetName(),
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	err = store.ChainTransaction(ctx, s.transactor,
		func(ctx context.Context, stores store.Stores) error {
			t := model.NewTenant(req.GetName(), req.GetLabels())
			t.ID = req.GetId()

			_, err := stores.Tenants.UpsertTenant(ctx, store.UpsertTenantQuery{Tenant: t})
			return err
		},
	)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "internal error"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &UpsertTenantResponse{}, nil
}
