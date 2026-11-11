package provider

import (
	"context"
	"errors"
	"uuid"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/sealer/providertest"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

// Service exposes the test provider through gRPC.
type Service struct {
	UnimplementedServiceServer

	provider *providertest.Provider
}

// NewService creates a service backed by the given test provider.
func NewService(provider *providertest.Provider) *Service {
	return &Service{provider: provider}
}

var _ ServiceServer = (*Service)(nil)

// CreateKey creates a provider key and its access token.
func (m *Service) CreateKey(ctx context.Context, _ *CreateKeyRequest) (*CreateKeyResponse, error) {
	auth, ref, err := m.provider.CreateKey(ctx)
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &CreateKeyResponse{
		KeyRef:      toProtoKeyRef(ref),
		AccessToken: string(auth.Token),
	}, nil
}

// RotateAuth replaces the access token for a provider key.
func (m *Service) RotateAuth(ctx context.Context, req *RotateAuthRequest) (*RotateAuthResponse, error) {
	if err := validateKeyID(req.GetKeyId()); err != nil {
		return nil, err
	}

	auth, err := m.provider.RotateAuth(ctx, req.GetKeyId())
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &RotateAuthResponse{AccessToken: string(auth.Token)}, nil
}

// RotateKey creates the next version of a provider key.
func (m *Service) RotateKey(ctx context.Context, req *RotateKeyRequest) (*RotateKeyResponse, error) {
	if err := validateKeyID(req.GetKeyId()); err != nil {
		return nil, err
	}

	ref, err := m.provider.RotateKey(ctx, req.GetKeyId())
	if err != nil {
		return nil, mapToProtoErr(err)
	}

	return &RotateKeyResponse{KeyRef: toProtoKeyRef(ref)}, nil
}

// DestroyKey removes a provider key, all its versions, and its access token.
func (m *Service) DestroyKey(ctx context.Context, req *DestroyKeyRequest) (*DestroyKeyResponse, error) {
	if err := validateKeyID(req.GetKeyId()); err != nil {
		return nil, err
	}

	if err := m.provider.DestroyKey(ctx, req.GetKeyId()); err != nil {
		return nil, mapToProtoErr(err)
	}

	return &DestroyKeyResponse{}, nil
}

func toProtoKeyRef(ref providertest.KeyRef) *KeyRef {
	return &KeyRef{
		KeyId:      ref.KeyID,
		KeyVersion: int32(ref.Version),
	}
}

func validateKeyID(keyID string) error {
	if _, err := uuid.Parse(keyID); err != nil {
		return proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, "key ID must be a valid UUID"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}
	return nil
}

func mapToProtoErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, providertest.ErrAuthNotFound):
		return proto.ErrDetailsWithCode(
			status.New(codes.NotFound, providertest.ErrAuthNotFound.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	case errors.Is(err, providertest.ErrKeyNotFound):
		return proto.ErrDetailsWithCode(
			status.New(codes.NotFound, providertest.ErrKeyNotFound.Error()),
			proto.Code_ERROR_CODE_ABORT,
		)
	default:
		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, "internal error"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
}
