package sealer

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/inline"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

type Router interface {
	LinkKey(ctx context.Context, req sealerprovider.LinkKeyRequest) error
	UnlinkKey(ctx context.Context, req sealerprovider.UnlinkKeyRequest) error
}

type RouterService struct {
	UnimplementedRouterServiceServer

	router Router
}

func NewRouterService(r Router) *RouterService {
	return &RouterService{router: r}
}

var _ RouterServiceServer = (*RouterService)(nil)

func (s *RouterService) LinkKey(ctx context.Context, req *LinkKeyRequest) (*LinkKeyResponse, error) {
	if err := validateLinkKeyRequest(req); err != nil {
		return nil, err
	}

	_, err := securemem.Run(ctx, func(ctx context.Context, _ *securemem.HandlerRequest) error {
		spec, err := providerToSpec(req.GetProvider())
		if err != nil {
			return err
		}
		if err := spec.Validate(); err != nil {
			return invalidArgument(err.Error())
		}

		if err := s.router.LinkKey(ctx, sealerprovider.LinkKeyRequest{
			Spec:       spec,
			TenantID:   req.GetTenantId(),
			KeyID:      req.GetKeyId(),
			ExternalID: req.GetExternalId(),
		}); err != nil {
			slog.Error("failed to link key", "error", err)
			return proto.ErrDetailsWithCode(
				status.New(codes.Internal, "failed to link key"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &LinkKeyResponse{}, nil
}

func (s *RouterService) UnlinkKey(ctx context.Context, req *UnlinkKeyRequest) (*UnlinkKeyResponse, error) {
	if err := validateUnlinkKeyRequest(req); err != nil {
		return nil, err
	}

	err := s.router.UnlinkKey(ctx, sealerprovider.UnlinkKeyRequest{
		TenantID: req.GetTenantId(),
		KeyID:    req.GetKeyId(),
	})
	if err != nil {
		slog.Error("failed to unlink key", "error", err)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to unlink key"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return &UnlinkKeyResponse{}, nil
}

func validateLinkKeyRequest(req *LinkKeyRequest) error {
	return validateIDs(req.GetTenantId(), req.GetKeyId())
}

func validateUnlinkKeyRequest(req *UnlinkKeyRequest) error {
	return validateIDs(req.GetTenantId(), req.GetKeyId())
}

func validateIDs(tenantID, keyID string) error {
	if validateUUID(tenantID) != nil {
		return invalidArgument(ErrInvalidTenantID.Error())
	}
	if validateUUID(keyID) != nil {
		return invalidArgument(ErrInvalidKeyID.Error())
	}
	return nil

}

func providerToSpec(p *Provider) (sealerprovider.Spec, error) {
	if p == nil {
		return sealerprovider.Spec{}, invalidArgument("provider is required")
	}

	switch v := p.GetProvider().(type) {
	case *Provider_StaticSecret:
		return staticSecretToSpec(v.StaticSecret)
	default:
		return sealerprovider.Spec{}, invalidArgument("unsupported provider")
	}
}

func staticSecretToSpec(ss *StaticSecretProvider) (sealerprovider.Spec, error) {
	if ss == nil {
		return sealerprovider.Spec{}, invalidArgument("static_secret is required")
	}

	material, err := securemem.NewData("link-key-material", len(ss.GetKeyMaterial()))
	if err != nil {
		return sealerprovider.Spec{}, invalidArgument(err.Error())
	}
	copy(material.SecureBytes(), ss.GetKeyMaterial())
	securemem.Zero(ss.GetKeyMaterial())

	return sealerprovider.Spec{
		Name: ss.GetName(),
		Type: staticsecret.TypeStaticSecret,
		Config: &staticsecret.Config{
			Secret: secretprovider.Spec{
				Type:   inline.Type,
				Config: &inline.Config{Material: material},
			},
		},
	}, nil
}

func invalidArgument(msg string) error {
	return proto.ErrDetailsWithCode(
		status.New(codes.InvalidArgument, msg),
		proto.Code_ERROR_CODE_ABORT,
	)
}
