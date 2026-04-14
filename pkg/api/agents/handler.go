package agents

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/openkcm/krypton/internal/clock"
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
	store     store.Agent
	hierarchy spec.KeyHierarchy
	topology  spec.Topology
}

// NewServerMux creates the admin API multiplexer with all routes registered.
func NewServerMux(mux *http.ServeMux, store store.Agent, hierarchy spec.KeyHierarchy, topology spec.Topology) http.Handler {
	if mux == nil {
		mux = http.NewServeMux()
	}
	a := &agent{hierarchy: hierarchy, store: store, topology: topology}
	mux.HandleFunc("POST "+PathRegister, a.register)
	mux.HandleFunc("POST "+PathHeartbeat, a.heartbeat)
	mux.HandleFunc("POST "+PathDeregister, a.deregister)
	return mux
}

// register handles the agent registration request.
func (a *agent) register(w http.ResponseWriter, r *http.Request) {
	xAgentName := r.Header.Get(AgentNameHeader)
	if xAgentName == "" {
		log.Println("missing X-Agent-Name header")
		http.Error(w, "missing X-Agent-Name header", http.StatusBadRequest)
		return
	}

	xAgentID := r.Header.Get(AgentIDHeader)
	if xAgentID == "" {
		log.Println("missing X-Agent-Id header")
		http.Error(w, "missing X-Agent-Id header", http.StatusBadRequest)
		return
	}

	seg, ok := a.topologySegment(xAgentName)
	if !ok {
		log.Printf("agent '%s' not found in topology", xAgentName)
		http.Error(w, "agent not found in topology", http.StatusNotFound)
		return
	}

	cfg := spec.NewAgentConfig(a.hierarchy, seg)

	_, err := a.store.Register(r.Context(), store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          xAgentName,
			InstanceID:    xAgentID,
			Status:        core.AgentRegistrationStatusRegistered,
			LastHeartbeat: clock.Now(),
		},
	})
	if err != nil {
		log.Printf("failed to register agent: %v", err)
		http.Error(w, "failed to register agent", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	err = json.NewEncoder(w).Encode(RegisterResponse{Config: cfg})
	if err != nil {
		log.Printf("failed to encode response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *agent) heartbeat(w http.ResponseWriter, r *http.Request) {
	xAgentName := r.Header.Get(AgentNameHeader)
	if xAgentName == "" {
		log.Println("missing X-Agent-Name header")
		http.Error(w, "missing X-Agent-Name header", http.StatusBadRequest)
		return
	}

	xAgentID := r.Header.Get(AgentIDHeader)
	if xAgentID == "" {
		log.Println("missing X-Agent-Id header")
		http.Error(w, "missing X-Agent-Id header", http.StatusBadRequest)
		return
	}

	_, ok := a.topologySegment(xAgentName)
	if !ok {
		log.Printf("agent '%s' not found in topology", xAgentName)
		http.Error(w, "agent not found in topology", http.StatusNotFound)
		return
	}

	_, err := a.store.Register(r.Context(), store.RegisterAgentQuery{
		Registration: core.AgentRegistration{
			Name:          xAgentName,
			InstanceID:    xAgentID,
			Status:        core.AgentRegistrationStatusHealthy,
			LastHeartbeat: clock.Now(),
		},
	})
	if err != nil {
		log.Printf("failed to update heartbeat: %v", err)
		http.Error(w, "failed to update heartbeat", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(SendHeartbeatResponse{})
	if err != nil {
		log.Printf("failed to encode response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *agent) deregister(w http.ResponseWriter, r *http.Request) {
	xAgentName := r.Header.Get(AgentNameHeader)
	if xAgentName == "" {
		log.Println("missing X-Agent-Name header")
		http.Error(w, "missing X-Agent-Name header", http.StatusBadRequest)
		return
	}

	xAgentID := r.Header.Get(AgentIDHeader)
	if xAgentID == "" {
		log.Println("missing X-Agent-Id header")
		http.Error(w, "missing X-Agent-Id header", http.StatusBadRequest)
		return
	}

	err := a.store.UpdateRegistrationStatus(r.Context(), store.UpdateRegistrationStatusQuery{
		Name:       xAgentName,
		InstanceID: xAgentID,
		FromStatus: []core.AgentRegistrationStatus{
			core.AgentRegistrationStatusRegistered,
			core.AgentRegistrationStatusHealthy,
			core.AgentRegistrationStatusUnhealthy,
		},
		ToStatus: core.AgentRegistrationStatusDeregistered,
	})
	if err != nil {
		log.Printf("failed to update agent status to deregistered : %v", err)
		http.Error(w, "failed to update agent status to deregistered ", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(DeregisterResponse{})
	if err != nil {
		log.Printf("failed to encode response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *agent) topologySegment(agentName string) (spec.TopologySegment, bool) {
	for _, seg := range a.topology.Segments {
		if seg.Name == agentName {
			return seg, true
		}
	}
	return spec.TopologySegment{}, false
}
