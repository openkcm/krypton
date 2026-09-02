package agents

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/pkg/api/v1/proto"
	"github.com/openkcm/krypton/pkg/store"
)

var _ ServiceServer = (*AgentService)(nil)

type AgentService struct {
	UnimplementedServiceServer

	store  store.Agent
	config config.RootConfig
}

// NewAgentService creates a new AgentService with the given store and config.
func NewAgentService(store store.Agent, config config.RootConfig) *AgentService {
	return &AgentService{
		store:  store,
		config: config,
	}
}

// Register registers an agent and returns its configuration.
// It validates the input, checks if the agent is defined in the topology, creates the
// agent config, stores the registration, and returns the config as YAML.
func (a *AgentService) Register(ctx context.Context, r *RegisterAgentRequest) (*RegisterAgentResponse, error) {
	agentName := r.GetAgentName()
	instanceID := r.GetInstanceId()
	err := validateInput(agentName, instanceID)
	if err != nil {
		return nil, err
	}

	seg := a.config.Topology.GetSegmentByName(agentName)
	if seg == nil {
		slog.Error("agent not found in topology", "agentName", agentName)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "agent not found in topology"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	var ids config.IdentityConfigs
	if a.config.Auth != nil {
		ids, err = a.config.AgentIdentities(agentName)
		if err != nil {
			slog.Error("failed to get agent identity configs", "agentName", agentName, "error", err)
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.FailedPrecondition, "failed to get agent identity configs"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
	}

	cfg := config.NewAgentConfig(a.config.Hierarchy, *seg, ids)

	pCfg, err := yaml.Marshal(cfg)
	if err != nil {
		slog.Error("failed to marshal agent config to yaml", "agentName", agentName, "error", err)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to marshal agent config to yaml"),
			proto.Code_ERROR_CODE_ABORT)
	}

	_, err = a.store.Register(ctx, store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          agentName,
			InstanceID:    instanceID,
			Status:        core.AgentRegistrationStatusRegistered,
			LastHeartbeat: clock.Now(),
		},
	})
	if err != nil {
		slog.Error("failed to register agent", "agentName", agentName, "instanceID", instanceID, "error", err)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to register agent"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &RegisterAgentResponse{
		Config: pCfg,
	}, nil
}

// SendHeartbeat updates the last heartbeat time of the agent.
func (a *AgentService) SendHeartbeat(ctx context.Context, r *SendHeartbeatRequest) (*SendHeartbeatResponse, error) {
	agentName := r.GetAgentName()
	instanceID := r.GetInstanceId()
	err := validateInput(agentName, instanceID)
	if err != nil {
		return nil, err
	}

	seg := a.config.Topology.GetSegmentByName(agentName)
	if seg == nil {
		slog.Error("agent not found in topology", "agentName", agentName)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "agent not found in topology"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	_, err = a.store.Register(ctx, store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          agentName,
			InstanceID:    instanceID,
			Status:        core.AgentRegistrationStatusHealthy,
			LastHeartbeat: clock.Now(),
		},
	})
	if err != nil {
		slog.Error("failed to update agent heartbeat", "agentName", agentName, "instanceID", instanceID, "error", err)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to update heartbeat"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &SendHeartbeatResponse{}, nil
}

// Deregister updates the agent status to deregistered.
func (a *AgentService) Deregister(ctx context.Context, r *DeregisterAgentRequest) (*DeregisterAgentResponse, error) {
	agentName := r.GetAgentName()
	instanceID := r.GetInstanceId()
	err := validateInput(agentName, instanceID)
	if err != nil {
		return nil, err
	}

	err = a.store.UpdateStatus(ctx, store.UpdateAgentStatusQuery{
		Name:       agentName,
		InstanceID: instanceID,
		FromStatus: []core.AgentRegistrationStatus{
			core.AgentRegistrationStatusRegistered,
			core.AgentRegistrationStatusHealthy,
			core.AgentRegistrationStatusUnhealthy,
		},
		ToStatus: core.AgentRegistrationStatusDeregistered,
	})
	if err != nil {
		slog.Error("failed to update agent status to deregistered", "agentName", agentName, "instanceID", instanceID, "error", err)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to update agent status to deregistered"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &DeregisterAgentResponse{}, nil
}

func UnmarshalAgentConfig(b []byte) (*config.AgentConfig, error) {
	var cfg config.AgentConfig
	err := yaml.Unmarshal(b, &cfg)
	if err != nil {
		slog.Error("failed to unmarshal agent config from yaml", "error", err)
		return nil, err
	}
	return &cfg, nil
}

func validateInput(agentName, instanceID string) error {
	if agentName == "" {
		slog.Error("agent name is required")
		return proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, "agent name is required"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}
	if instanceID == "" {
		slog.Error("instance ID is required")
		return proto.ErrDetailsWithCode(
			status.New(codes.InvalidArgument, "instance ID is required"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}
	return nil
}
