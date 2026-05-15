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

type TenantService struct {
	UnimplementedTenantServiceServer

	store store.Tenant
}

func NewTenantService(s store.Tenant) *TenantService {
	return &TenantService{store: s}
}

func (s *TenantService) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*CreateTenantResponse, error) {
	tenant := model.NewTenant(req.GetName(), req.GetLabels())

	result, err := s.store.CreateTenant(ctx, store.CreateTenantQuery{
		Tenant: tenant,
	})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to create tenant"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &CreateTenantResponse{
		Tenant: TenantToProto(result.Tenant),
	}, nil
}

func (s *TenantService) GetTenant(ctx context.Context, req *GetTenantRequest) (*GetTenantResponse, error) {
	result, err := s.store.GetTenant(ctx, store.GetTenantQuery{
		ID: req.GetId(),
	})
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.NotFound, "tenant not found"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get tenant"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &GetTenantResponse{
		Tenant: TenantToProto(result.Tenant),
	}, nil
}

func (s *TenantService) ListTenants(ctx context.Context, _ *ListTenantsRequest) (*ListTenantsResponse, error) {
	result, err := s.store.ListTenants(ctx, store.ListTenantsQuery{})
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to list tenants"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &ListTenantsResponse{
		Tenants: TenantsToProto(result.Tenants),
	}, nil
}
