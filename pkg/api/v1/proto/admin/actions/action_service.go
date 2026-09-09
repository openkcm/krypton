package actions

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ActionService is the resource-agnostic gRPC service for inspecting the
// long-running actions issued against krypton resources.
//
// TODO: implement once orbital JobGroups are wired in.
// TODO(auth): add authorization check before returning.
type ActionService struct {
	UnimplementedActionServiceServer
}

func NewActionService() *ActionService {
	return &ActionService{}
}

func (s *ActionService) GetAction(_ context.Context, _ *GetActionRequest) (*GetActionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "method GetAction not implemented")
}
