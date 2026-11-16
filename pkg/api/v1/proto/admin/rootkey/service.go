package rootkey

import (
	"context"
	"errors"
	"uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/providertest"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/validator"
)

// Service manages root key provider bindings through the gRPC API.
type Service struct {
	UnimplementedServiceServer

	root *keyprocessor.RootManager
}

// NewService creates a root key provider service backed by the given root manager.
func NewService(root *keyprocessor.RootManager) *Service {
	return &Service{root: root}
}

var _ ServiceServer = (*Service)(nil)

var (
	// ErrInvalidTenantID means the tenant ID is not a valid UUID.
	ErrInvalidTenantID = errors.New("tenant ID must be a valid UUID")
	// ErrInvalidKeyID means the key ID is not a valid UUID.
	ErrInvalidKeyID = errors.New("key ID must be a valid UUID")
	// ErrProviderKeyRequired means no provider key was specified.
	ErrProviderKeyRequired = errors.New("provider key is required")
	// ErrUnsupportedProvider means the selected provider is not supported.
	ErrUnsupportedProvider = errors.New("provider is not supported")
)

// CreateProvider creates a provider binding for the specified root key.
// TODO: Keep provider auth in securemem-backed buffers and wipe transient plaintext copies after use.
func (s *Service) CreateProvider(ctx context.Context, req *CreateProviderRequest) (*CreateProviderResponse, error) {
	if err := validateIDs(req.GetTenantId(), req.GetKeyId()); err != nil {
		return nil, err
	}

	spec, providerKeyID, err := provider(req.GetProvider())
	if err != nil {
		return nil, err
	}

	err = s.root.CreateProvider(ctx, keyprocessor.CreateProviderInput{
		TenantID:      req.GetTenantId(),
		KeyID:         req.GetKeyId(),
		Spec:          spec,
		ProviderKeyID: providerKeyID,
	})
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &CreateProviderResponse{}, nil
}

// RotateAuth updates the authentication for a root key's provider binding.
// TODO: Keep provider auth in securemem-backed buffers and wipe transient plaintext copies after use.
func (s *Service) RotateAuth(ctx context.Context, req *RotateAuthRequest) (*RotateAuthResponse, error) {
	if err := validateIDs(req.GetTenantId(), req.GetKeyId()); err != nil {
		return nil, err
	}

	t, auth, err := providerAuth(req.GetAuth())
	if err != nil {
		return nil, err
	}

	err = s.root.RotateAuth(ctx, keyprocessor.RotateAuthInput{
		TenantID: req.GetTenantId(),
		KeyID:    req.GetKeyId(),
		Type:     t,
		Auth:     auth,
	})
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &RotateAuthResponse{}, nil
}

// RotateProviderKey changes the provider key referenced by a root key's binding.
func (s *Service) RotateProviderKey(ctx context.Context, req *RotateProviderKeyRequest) (*RotateProviderKeyResponse, error) {
	if err := validateIDs(req.GetTenantId(), req.GetKeyId()); err != nil {
		return nil, err
	}

	t, providerKeyID, err := providerKey(req.GetProviderKey())
	if err != nil {
		return nil, err
	}

	err = s.root.RotateProviderKey(ctx, keyprocessor.RotateProviderKeyInput{
		TenantID:      req.GetTenantId(),
		KeyID:         req.GetKeyId(),
		Type:          t,
		ProviderKeyID: providerKeyID,
	})
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &RotateProviderKeyResponse{}, nil
}

// RemoveProvider removes the provider binding from the specified root key.
func (s *Service) RemoveProvider(ctx context.Context, req *RemoveProviderRequest) (*RemoveProviderResponse, error) {
	if err := validateIDs(req.GetTenantId(), req.GetKeyId()); err != nil {
		return nil, err
	}

	err := s.root.RemoveProvider(ctx, keyprocessor.RemoveProviderInput{
		TenantID: req.GetTenantId(),
		KeyID:    req.GetKeyId(),
	})
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &RemoveProviderResponse{}, nil
}

func provider(p *Provider) (sealerprovider.Spec, string, error) {
	switch p := p.GetProvider().(type) {
	case *Provider_TestProvider:
		return testProvider(p.TestProvider)
	case *Provider_AwsKms:
		return sealerprovider.Spec{}, "", unsupportedProvider() // aws_kms not yet supported
	default:
		return sealerprovider.Spec{}, "", unsupportedProvider()
	}
}

func testProvider(p *TestProvider) (sealerprovider.Spec, string, error) {
	config := &providertest.Config{InstanceID: p.GetConfig().GetInstanceId()}
	if err := config.ValidateSealerConfig(); err != nil {
		return sealerprovider.Spec{}, "", invalidArgument(err)
	}

	auth := &providertest.Auth{Token: providertest.AccessToken(p.GetAuth().GetAccessToken())}
	if err := auth.ValidateSealerAuth(); err != nil {
		return sealerprovider.Spec{}, "", invalidArgument(err)
	}

	providerKeyID := p.GetProviderKey().GetKeyId()
	if providerKeyID == "" {
		return sealerprovider.Spec{}, "", invalidArgument(ErrProviderKeyRequired)
	}

	return sealerprovider.Spec{
		Name:   config.InstanceID,
		Type:   providertest.TypeProviderTest,
		Config: config,
		Auth:   auth,
	}, providerKeyID, nil
}

func providerKey(key *ProviderKey) (sealer.Type, string, error) {
	switch k := key.GetProvider().(type) {
	case *ProviderKey_TestProvider:
		id := k.TestProvider.GetKeyId()
		if id == "" {
			return "", "", invalidArgument(ErrProviderKeyRequired)
		}
		return providertest.TypeProviderTest, id, nil
	case *ProviderKey_AwsKms:
		return "", "", unsupportedProvider() // aws_kms not yet supported
	default:
		return "", "", unsupportedProvider()
	}
}

func providerAuth(auth *ProviderAuth) (sealer.Type, sealer.SealerAuth, error) {
	switch a := auth.GetProvider().(type) {
	case *ProviderAuth_TestProvider:
		providerAuth := &providertest.Auth{Token: providertest.AccessToken(a.TestProvider.GetAccessToken())}
		if err := providerAuth.ValidateSealerAuth(); err != nil {
			return "", nil, invalidArgument(err)
		}
		return providertest.TypeProviderTest, providerAuth, nil
	case *ProviderAuth_AwsKms:
		return "", nil, unsupportedProvider() // aws_kms not yet supported
	default:
		return "", nil, unsupportedProvider()
	}
}

func validateIDs(tenantID, keyID string) error {
	if _, err := uuid.Parse(tenantID); err != nil {
		return invalidArgument(ErrInvalidTenantID)
	}
	if _, err := uuid.Parse(keyID); err != nil {
		return invalidArgument(ErrInvalidKeyID)
	}
	return nil
}

func invalidArgument(err error) error {
	return proto.ErrDetailsWithCode(
		status.New(codes.InvalidArgument, err.Error()),
		proto.Code_ERROR_CODE_ABORT,
	)
}

func unsupportedProvider() error {
	return proto.ErrDetailsWithCode(
		status.New(codes.Unimplemented, ErrUnsupportedProvider.Error()),
		proto.Code_ERROR_CODE_ABORT,
	)
}

func mapToProtoErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrKeyNotFound), errors.Is(err, vault.ErrSecretNotFound):
		return proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "key not found"),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, store.ErrTenantNotFound):
		return proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "tenant not found"),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errorIsOneOf(err,
		keyprocessor.ErrProviderNotAllowed,
		keyprocessor.ErrProviderTypeMismatch,
		keyprocessor.ErrNoProviderKeyVersion,
		validator.ErrKeyTransientState,
		validator.ErrInvalidKey):
		return proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, err.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	default:
		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, "internal error"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
}

func errorIsOneOf(err error, trgts ...error) bool {
	for _, trgt := range trgts {
		if errors.Is(err, trgt) {
			return true
		}
	}
	return false
}
