package actions

import (
	"context"
	"fmt"
	"strconv"
	"uuid"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/handler/announcekey"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

// Label keys carrying action metadata on an orbital.JobGroup. The "krypton/"
// prefix stays clear of orbital's reserved "orbital/" namespace.
const (
	LabelKeyTargetType = "krypton/action-target-type"
	LabelKeyTargetID   = "krypton/action-target-id"
	LabelKeyCascading  = "krypton/action-cascading"
)

// actionTypeByJobGroupType maps an orbital JobGroup.Type to an ActionType.
var actionTypeByJobGroupType = map[string]ActionType{
	announcekey.JobGroupType: ActionType_ANNOUNCE_KEY,
}

// JobGroupStore retrieves orbital job groups backing actions.
type JobGroupStore interface {
	GetJobGroup(ctx context.Context, groupID uuid.UUID) (orbital.JobGroup, bool, error)
}

// Service implements the ActionService gRPC server.
type Service struct {
	UnimplementedActionServiceServer

	store JobGroupStore
}

// NewService returns a Service backed by the given JobGroupStore.
func NewService(store JobGroupStore) *Service {
	return &Service{
		store: store,
	}
}

// GetAction returns the action for the given id, or a gRPC status error if the
// id is invalid or no matching action exists.
func (s *Service) GetAction(ctx context.Context, req *GetActionRequest) (*GetActionResponse, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, "invalid action id"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	group, found, err := s.store.GetJobGroup(ctx, id)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get action"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
	if !found {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "action not found"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	action, err := jobGroupToAction(group)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "action not found"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return &GetActionResponse{Action: action}, nil
}

// jobGroupToAction converts a JobGroup to an Action, erroring on an unknown job
// group type.
func jobGroupToAction(jg orbital.JobGroup) (*Action, error) {
	actionType, ok := actionTypeByJobGroupType[jg.Type]
	if !ok {
		return nil, fmt.Errorf("unknown job group type %q", jg.Type)
	}

	return &Action{
		Id:         jg.ID.String(),
		Type:       actionType,
		Status:     string(jg.Status),
		TargetType: TargetType(TargetType_value[jg.Labels[LabelKeyTargetType]]),
		TargetId:   jg.Labels[LabelKeyTargetID],
		Cascading:  cascadingFromLabels(jg.Labels),
		CreatedAt:  jg.CreatedAt,
		UpdatedAt:  jg.UpdatedAt,
	}, nil
}

// cascadingFromLabels reads the cascading label, defaulting to false when
// absent or invalid.
func cascadingFromLabels(labels orbital.Labels) bool {
	cascading, err := strconv.ParseBool(labels[LabelKeyCascading])
	return err == nil && cascading
}
