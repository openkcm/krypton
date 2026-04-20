package agents

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/config"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/store"
)

type (
	RegisterRequest  struct{}
	RegisterResponse struct {
		Config spec.AgentConfig `json:"config"`
	}
	SendHeartbeatRequest  struct{}
	SendHeartbeatResponse struct{}
	DeregisterRequest     struct{}
	DeregisterResponse    struct{}
)

const (
	PathRegister    = "/api/v1/agents/register"
	PathHeartbeat   = "/api/v1/agents/heartbeat"
	PathDeregister  = "/api/v1/agents/deregister"
	AgentNameHeader = "X-Agent-Name"
	AgentIDHeader   = "X-Agent-Id"
)

type agent struct {
	store  store.Agent
	config config.RootConfig
}

type agentHeader struct {
	agentName string
	agentID   string
}

var errHeaderMissing = errors.New("required header is missing")

// NewServerMux creates the admin API multiplexer with all routes registered.
func NewServerMux(mux *http.ServeMux, store store.Agent, root config.RootConfig) *http.ServeMux {
	if mux == nil {
		mux = http.NewServeMux()
	}
	a := &agent{store: store, config: root}
	mux.HandleFunc("POST "+PathRegister, a.register)
	mux.HandleFunc("POST "+PathHeartbeat, a.heartbeat)
	mux.HandleFunc("POST "+PathDeregister, a.deregister)
	return mux
}

// register handles the agent registration request.
func (a *agent) register(w http.ResponseWriter, r *http.Request) {
	ah, err := extractAgentHeaders(w, r)
	if err != nil {
		return
	}

	seg, ok := a.topologySegment(ah.agentName)
	if !ok {
		log.Printf("agent '%s' not found in topology", ah.agentName)
		http.Error(w, "agent not found in topology", http.StatusNotFound)
		return
	}

	cfg := spec.NewAgentConfig(a.config.Hierarchy, seg)

	_, err = a.store.Register(r.Context(), store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          ah.agentName,
			InstanceID:    ah.agentID,
			Status:        core.AgentRegistrationStatusRegistered,
			LastHeartbeat: clock.Now(),
		},
	})
	if err != nil {
		log.Printf("failed to register agent: %v", err)
		http.Error(w, "failed to register agent", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, RegisterResponse{Config: cfg})
}

func (a *agent) heartbeat(w http.ResponseWriter, r *http.Request) {
	ah, err := extractAgentHeaders(w, r)
	if err != nil {
		return
	}

	_, ok := a.topologySegment(ah.agentName)
	if !ok {
		log.Printf("agent '%s' not found in topology", ah.agentName)
		http.Error(w, "agent not found in topology", http.StatusNotFound)
		return
	}

	_, err = a.store.Register(r.Context(), store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          ah.agentName,
			InstanceID:    ah.agentID,
			Status:        core.AgentRegistrationStatusHealthy,
			LastHeartbeat: clock.Now(),
		},
	})
	if err != nil {
		log.Printf("failed to update heartbeat: %v", err)
		http.Error(w, "failed to update heartbeat", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, SendHeartbeatResponse{})
}

func (a *agent) deregister(w http.ResponseWriter, r *http.Request) {
	ah, err := extractAgentHeaders(w, r)
	if err != nil {
		return
	}

	err = a.store.UpdateStatus(r.Context(), store.UpdateAgentStatusQuery{
		Name:       ah.agentName,
		InstanceID: ah.agentID,
		FromStatus: []core.AgentRegistrationStatus{
			core.AgentRegistrationStatusRegistered,
			core.AgentRegistrationStatusHealthy,
			core.AgentRegistrationStatusUnhealthy,
		},
		ToStatus: core.AgentRegistrationStatusDeregistered,
	})
	if err != nil {
		log.Printf("failed to update agent status to deregistered : %v", err)
		http.Error(w, "failed to update agent status to deregistered", http.StatusInternalServerError)
		return
	}

	writeJSONResponse(w, DeregisterResponse{})
}

func extractAgentHeaders(w http.ResponseWriter, r *http.Request) (agentHeader, error) {
	agentName := r.Header.Get(AgentNameHeader)
	if agentName == "" {
		log.Println("missing X-Agent-Name header")
		http.Error(w, "missing X-Agent-Name header", http.StatusBadRequest)
		return agentHeader{}, errHeaderMissing
	}

	agentID := r.Header.Get(AgentIDHeader)
	if agentID == "" {
		log.Println("missing X-Agent-Id header")
		http.Error(w, "missing X-Agent-Id header", http.StatusBadRequest)
		return agentHeader{}, errHeaderMissing
	}
	return agentHeader{agentName: agentName, agentID: agentID}, nil
}

func writeJSONResponse(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(body)
	if err != nil {
		log.Printf("failed to encode response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *agent) topologySegment(agentName string) (spec.TopologySegment, bool) {
	for _, seg := range a.config.Topology.Segments {
		if seg.Name == agentName {
			return seg, true
		}
	}
	return spec.TopologySegment{}, false
}
