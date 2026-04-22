package admin

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	admingrpc "github.com/openkcm/krypton/pkg/api/admin/v1/proto"
	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// Service implements the gRPC AdminService server.
type Service struct {
	admingrpc.UnimplementedServiceServer

	store store.Tenant
}

// NewService creates a new Service with the given tenant store.
func NewService(s store.Tenant) *Service {
	return &Service{store: s}
}

// CreateTenant creates a new tenant.
func (s *Service) CreateTenant(ctx context.Context, req *admingrpc.CreateTenantRequest) (*admingrpc.CreateTenantResponse, error) {
	tenant := model.NewTenant(req.GetName(), req.GetLabels())

	result, err := s.store.CreateTenant(ctx, store.CreateTenantQuery{
		Tenant: tenant,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create tenant")
	}

	return &admingrpc.CreateTenantResponse{
		Tenant: TenantToProto(result.Tenant),
	}, nil
}

// GetTenant retrieves a tenant by ID.
func (s *Service) GetTenant(ctx context.Context, req *admingrpc.GetTenantRequest) (*admingrpc.GetTenantResponse, error) {
	result, err := s.store.GetTenant(ctx, store.GetTenantQuery{
		ID: req.GetId(),
	})
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		}
		return nil, status.Error(codes.Internal, "failed to get tenant")
	}

	return &admingrpc.GetTenantResponse{
		Tenant: TenantToProto(result.Tenant),
	}, nil
}

// ListTenants returns all tenants.
func (s *Service) ListTenants(ctx context.Context, _ *admingrpc.ListTenantsRequest) (*admingrpc.ListTenantsResponse, error) {
	result, err := s.store.ListTenants(ctx, store.ListTenantsQuery{})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list tenants")
	}

	return &admingrpc.ListTenantsResponse{
		Tenants: TenantsToProto(result.Tenants),
	}, nil
}
