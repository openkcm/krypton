package provider

import (
	"context"
	"errors"

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

// UpsertInstance creates a provider instance if it does not exist.
func (m *Service) UpsertInstance(ctx context.Context, req *UpsertInstanceRequest) (*UpsertInstanceResponse, error) {
	if err := m.provider.UpsertInstance(ctx, req.GetInstanceId()); err != nil {
		return nil, mapToProtoErr(err)
	}
	return &UpsertInstanceResponse{}, nil
}

// UpsertKey generates key material in a provider instance.
func (m *Service) UpsertKey(ctx context.Context, req *UpsertKeyRequest) (*UpsertKeyResponse, error) {
	if err := m.provider.UpsertKey(ctx, req.GetInstanceId(), req.GetKeyId()); err != nil {
		return nil, mapToProtoErr(err)
	}
	return &UpsertKeyResponse{}, nil
}

// UpsertKeyAuth stores key-bound auth for a provider instance.
func (m *Service) UpsertKeyAuth(ctx context.Context, req *UpsertKeyAuthRequest) (*UpsertKeyAuthResponse, error) {
	err := m.provider.UpsertKeyAuth(ctx, req.GetInstanceId(), req.GetKeyId(), providertest.AccessToken(req.GetAccessToken()))
	if err != nil {
		return nil, mapToProtoErr(err)
	}
	return &UpsertKeyAuthResponse{}, nil
}

// DeleteInstance removes a provider instance.
func (m *Service) DeleteInstance(_ context.Context, req *DeleteInstanceRequest) (*DeleteInstanceResponse, error) {
	if err := m.provider.DeleteInstance(req.GetInstanceId()); err != nil {
		return nil, mapToProtoErr(err)
	}
	return &DeleteInstanceResponse{}, nil
}

func mapToProtoErr(err error) error {
	switch {
	case errors.Is(err, providertest.ErrInstanceNotFound):
		return abort(codes.NotFound, err.Error())
	case errors.Is(err, providertest.ErrInstanceIDMissing),
		errors.Is(err, providertest.ErrKeyIDMissing),
		errors.Is(err, providertest.ErrAccessTokenMissing):
		return abort(codes.InvalidArgument, err.Error())
	default:
		return proto.ErrDetailsWithCode(
			status.New(codes.Internal, "internal error"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
}

func abort(code codes.Code, message string) error {
	return proto.ErrDetailsWithCode(
		status.New(code, message),
		proto.Code_ERROR_CODE_ABORT,
	)
}
