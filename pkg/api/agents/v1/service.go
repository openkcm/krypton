package v1

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/api/agents/v1/proto"
	"github.com/openkcm/krypton/pkg/store"
)

var _ proto.AgentServiceServer = (*AgentService)(nil)

type AgentService struct {
	proto.UnimplementedAgentServiceServer

	store  store.Agent
	config config.RootConfig
}

func NewAgentService(store store.Agent, config config.RootConfig) *AgentService {
	return &AgentService{
		store:  store,
		config: config,
	}
}

// Register implements [proto.AgentServiceServer].
func (a *AgentService) Register(ctx context.Context, r *proto.RegisterAgentRequest) (*proto.RegisterAgentResponse, error) {
	agentName := r.GetAgentName()
	instanceID := r.GetInstanceId()
	err := validateInput(agentName, instanceID)
	if err != nil {
		return nil, err
	}

	seg, ok := a.topologySegment(agentName)
	if !ok {
		slog.Error("agent not found in topology", "agentName", agentName)
		return nil, status.Error(codes.NotFound, "agent not found in topology")
	}

	cfg := spec.NewAgentConfig(a.config.Hierarchy, seg)

	pCfg, err := AgentConfigToProto(cfg)
	if err != nil {
		slog.Error("failed to convert agent config to proto", "agentName", agentName, "error", err)
		return nil, status.Error(codes.Internal, "failed to convert agent config to proto")
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
		return nil, status.Error(codes.Internal, "failed to register agent")
	}

	return &proto.RegisterAgentResponse{
		Config: pCfg,
	}, nil
}

// SendHeartbeat implements [proto.AgentServiceServer].
func (a *AgentService) SendHeartbeat(ctx context.Context, r *proto.SendHeartbeatRequest) (*proto.SendHeartbeatResponse, error) {
	agentName := r.GetAgentName()
	instanceID := r.GetInstanceId()
	err := validateInput(agentName, instanceID)
	if err != nil {
		return nil, err
	}

	_, ok := a.topologySegment(agentName)
	if !ok {
		slog.Error("agent not found in topology", "agentName", agentName)
		return nil, status.Error(codes.NotFound, "agent not found in topology")
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
		return nil, status.Error(codes.Internal, "failed to update heartbeat")
	}

	return &proto.SendHeartbeatResponse{}, nil
}

// Deregister implements [proto.AgentServiceServer].
func (a *AgentService) Deregister(ctx context.Context, r *proto.DeregisterAgentRequest) (*proto.DeregisterAgentResponse, error) {
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
		return nil, status.Error(codes.Internal, "failed to update agent status to deregistered")
	}

	return &proto.DeregisterAgentResponse{}, nil
}

func (a *AgentService) topologySegment(agentName string) (spec.TopologySegment, bool) {
	for _, seg := range a.config.Topology.Segments {
		if seg.Name == agentName {
			return seg, true
		}
	}
	return spec.TopologySegment{}, false
}

func validateInput(agentName, instanceID string) error {
	if agentName == "" {
		return status.Error(codes.InvalidArgument, "agent name is required")
	}
	if instanceID == "" {
		return status.Error(codes.InvalidArgument, "instance ID is required")
	}
	return nil
}
