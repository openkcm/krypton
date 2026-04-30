package admin

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

// Service implements the gRPC AdminService server.
type Service struct {
	UnimplementedServiceServer

	store store.Tenant
}

// NewService creates a new Service with the given tenant store.
func NewService(s store.Tenant) *Service {
	return &Service{store: s}
}

// CreateTenant creates a new tenant.
func (s *Service) CreateTenant(ctx context.Context, req *CreateTenantRequest) (*CreateTenantResponse, error) {
	tenant := model.NewTenant(req.GetName(), req.GetLabels())

	result, err := s.store.CreateTenant(ctx, store.CreateTenantQuery{
		Tenant: tenant,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to create tenant")
	}

	return &CreateTenantResponse{
		Tenant: TenantToProto(result.Tenant),
	}, nil
}

// GetTenant retrieves a tenant by ID.
func (s *Service) GetTenant(ctx context.Context, req *GetTenantRequest) (*GetTenantResponse, error) {
	result, err := s.store.GetTenant(ctx, store.GetTenantQuery{
		ID: req.GetId(),
	})
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			return nil, status.Error(codes.NotFound, "tenant not found")
		}
		return nil, status.Error(codes.Internal, "failed to get tenant")
	}

	return &GetTenantResponse{
		Tenant: TenantToProto(result.Tenant),
	}, nil
}

// ListTenants returns all tenants.
func (s *Service) ListTenants(ctx context.Context, _ *ListTenantsRequest) (*ListTenantsResponse, error) {
	result, err := s.store.ListTenants(ctx, store.ListTenantsQuery{})
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list tenants")
	}

	return &ListTenantsResponse{
		Tenants: TenantsToProto(result.Tenants),
	}, nil
}
