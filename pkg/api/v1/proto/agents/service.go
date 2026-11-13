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
func (m *AgentService) Register(ctx context.Context, r *RegisterAgentRequest) (*RegisterAgentResponse, error) {
	// TODO: Get agentname from the authenticated context instead of the request, to prevent spoofing.
	an := r.GetAgentName()
	id := r.GetInstanceId()
	err := validateInput(an, id)
	if err != nil {
		return nil, err
	}

	seg := m.config.Topology.GetSegmentByName(an)
	if seg == nil {
		slog.Error("agent not found in topology", "agentName", an)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "agent not found in topology"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	var ids config.IdentityConfigs
	if m.config.Auth != nil {
		ids, err = m.config.AgentIdentities(an)
		if err != nil {
			slog.Error("failed to get agent identity configs", "agentName", an, "error", err)
			return nil, proto.ErrDetailsWithCode(
				status.New(codes.FailedPrecondition, "failed to get agent identity configs"),
				proto.Code_ERROR_CODE_ABORT,
			)
		}
	}

	pn, ok := m.config.Topology.ParentName(an)
	if !ok {
		slog.Error("parent agent not found in topology", "agentName", an)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, "parent agent not found in topology"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	ccs, err := m.config.Connections.ByNames(pn)
	if err != nil {
		slog.Error("failed to get connection configs", "agentName", an, "error", err)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.FailedPrecondition, "failed to get connection configs"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	kc := m.lookupKMIP(an)

	cfg := config.NewAgentConfig(m.config.Hierarchy, *seg, ids, ccs, kc)

	b, err := yaml.Marshal(cfg)
	if err != nil {
		slog.Error("failed to marshal agent config to yaml", "agentName", an, "error", err)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to marshal agent config to yaml"),
			proto.Code_ERROR_CODE_ABORT)
	}

	_, err = m.store.Register(ctx, store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          an,
			InstanceID:    id,
			Status:        core.AgentRegistrationStatusRegistered,
			LastHeartbeat: clock.Now(),
		},
	})
	if err != nil {
		slog.Error("failed to register agent", "agentName", an, "instanceID", id, "error", err)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.Internal, "failed to register agent"),
			proto.Code_ERROR_CODE_RETRY,
		)
	}

	return &RegisterAgentResponse{
		Config: b,
	}, nil
}

func (m *AgentService) lookupKMIP(agentName string) *config.KMIP {
	cfg, ok := m.config.KMIPs.ByName(agentName)
	if ok {
		return &cfg
	}
	return nil
}

// SendHeartbeat updates the last heartbeat time of the agent.
func (m *AgentService) SendHeartbeat(ctx context.Context, r *SendHeartbeatRequest) (*SendHeartbeatResponse, error) {
	agentName := r.GetAgentName()
	instanceID := r.GetInstanceId()
	err := validateInput(agentName, instanceID)
	if err != nil {
		return nil, err
	}

	seg := m.config.Topology.GetSegmentByName(agentName)
	if seg == nil {
		slog.Error("agent not found in topology", "agentName", agentName)
		return nil, proto.ErrDetailsWithCode(
			status.New(codes.NotFound, "agent not found in topology"),
			proto.Code_ERROR_CODE_ABORT,
		)
	}

	_, err = m.store.Register(ctx, store.RegisterAgentQuery{
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
func (m *AgentService) Deregister(ctx context.Context, r *DeregisterAgentRequest) (*DeregisterAgentResponse, error) {
	agentName := r.GetAgentName()
	instanceID := r.GetInstanceId()
	err := validateInput(agentName, instanceID)
	if err != nil {
		return nil, err
	}

	err = m.store.UpdateStatus(ctx, store.UpdateAgentStatusQuery{
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
