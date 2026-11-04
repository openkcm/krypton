package rootkey

import (
	"context"
	"encoding/base64"
	"errors"
	"uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/keyprocessor"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/sealerprovider"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/inline"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
	"github.com/openkcm/krypton/internal/securemem"
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
	// ErrSecretRequired means no static secret was specified.
	ErrSecretRequired = errors.New("secret is required")
	// ErrProviderMismatch means the provider inputs select different providers.
	ErrProviderMismatch = errors.New("provider config and provider key must use the same provider")
	// ErrUnsupportedProvider means the selected provider is not supported.
	ErrUnsupportedProvider = errors.New("provider is not supported")
)

// CreateProvider creates a provider binding for the specified root key.
// TODO: Keep provider auth in securemem-backed buffers and wipe transient plaintext copies after use.
func (s *Service) CreateProvider(ctx context.Context, req *CreateProviderRequest) (*CreateProviderResponse, error) {
	if err := validateIDs(req.GetTenantId(), req.GetKeyId()); err != nil {
		return nil, err
	}

	keyType, providerKeyID, err := providerKey(req.GetProviderKey())
	if err != nil {
		return nil, err
	}

	authType, auth, err := providerAuth(req.GetAuth())
	if err != nil {
		return nil, err
	}

	spec, err := providerSpec(req.GetConfig())
	if err != nil {
		return nil, err
	}

	typesMatch := spec.Type == authType && spec.Type == keyType
	if !typesMatch {
		return nil, invalidArgument(ErrProviderMismatch)
	}
	spec.Auth = auth

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

func providerSpec(cfg *ProviderConfig) (sealerprovider.Spec, error) {
	switch c := cfg.GetProvider().(type) {
	case *ProviderConfig_StaticSecret:
		return staticSecretSpec(c.StaticSecret)
	case *ProviderConfig_AwsKms:
		return sealerprovider.Spec{}, unsupportedProvider() // aws_kms not yet supported
	default:
		return sealerprovider.Spec{}, unsupportedProvider()
	}
}

func providerKey(key *ProviderKey) (sealer.Type, string, error) {
	switch k := key.GetProvider().(type) {
	case *ProviderKey_StaticSecret:
		id := k.StaticSecret.GetId()
		if id == "" {
			return "", "", invalidArgument(ErrProviderKeyRequired)
		}
		return staticsecret.TypeStaticSecret, id, nil
	case *ProviderKey_AwsKms:
		return "", "", unsupportedProvider() // aws_kms not yet supported
	default:
		return "", "", unsupportedProvider()
	}
}

func providerAuth(auth *ProviderAuth) (sealer.Type, sealer.SealerAuth, error) {
	switch auth.GetProvider().(type) {
	case *ProviderAuth_StaticSecret:
		return staticsecret.TypeStaticSecret, &staticsecret.Auth{}, nil
	case *ProviderAuth_AwsKms:
		return "", nil, unsupportedProvider() // aws_kms not yet supported
	default:
		return "", nil, unsupportedProvider()
	}
}

func staticSecretSpec(cfg *StaticSecretConfig) (sealerprovider.Spec, error) {
	raw := cfg.GetSecret()
	if len(raw) == 0 {
		return sealerprovider.Spec{}, invalidArgument(ErrSecretRequired)
	}
	defer securemem.Zero(raw)

	buf := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(buf, raw)
	defer securemem.Zero(buf)

	spec := sealerprovider.Spec{
		Name: cfg.GetSecretName(),
		Type: staticsecret.TypeStaticSecret,
		Config: &staticsecret.Config{
			Secret: secretprovider.Spec{
				Type:   inline.Type,
				Config: &inline.Config{Secret: string(buf)},
			},
		},
	}
	return spec, nil
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
	case errors.Is(err, store.ErrKeyNotFound), errors.Is(err, vault.ErrKeyNotFound):
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
