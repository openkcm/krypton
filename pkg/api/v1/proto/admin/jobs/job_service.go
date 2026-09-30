package jobs

import (
	"context"
	"uuid"

	"github.com/openkcm/orbital"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/pkg/api/v1/proto"
)

// JobGroupProvider reads a job group (with its jobs populated) by ID. The root
// orchestrator satisfies it.
type JobGroupProvider interface {
	GetJobGroup(ctx context.Context, groupID uuid.UUID) (orbital.JobGroup, bool, error)
}

// JobService serves read-only queries over orbital job groups, letting callers
// poll the progress of a cascading key activation.
type JobService struct {
	UnimplementedJobServiceServer

	provider JobGroupProvider
}

// NewJobService constructs the admin job service.
func NewJobService(provider JobGroupProvider) *JobService {
	return &JobService{provider: provider}
}

func (s *JobService) GetJobGroup(ctx context.Context, req *GetJobGroupRequest) (*GetJobGroupResponse, error) {
	id, err := uuid.Parse(req.GetId())
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, "invalid job group id"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	group, found, err := s.provider.GetJobGroup(ctx, id)
	if err != nil {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to get job group"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}
	if !found {
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "job group not found"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	return &GetJobGroupResponse{JobGroup: jobGroupToProto(group)}, nil
}

func jobGroupToProto(group orbital.JobGroup) *JobGroup {
	jobList := make([]*Job, 0, len(group.Jobs))
	for _, job := range group.Jobs {
		jobList = append(jobList, &Job{
			Id:           job.ID.String(),
			Type:         job.Type,
			Status:       string(job.Status),
			ErrorMessage: job.ErrorMessage,
		})
	}

	return &JobGroup{
		Id:           group.ID.String(),
		Type:         group.Type,
		Status:       string(group.Status),
		ErrorMessage: group.ErrorMessage,
		Jobs:         jobList,
	}
}
