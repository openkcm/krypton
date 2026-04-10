package agents

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/spec"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/store/sql"
)

type (
	RegisterRequest  struct{}
	RegisterResponse struct {
		Config spec.AgentConfig `json:"config"`
	}
)

const (
	PathRegister    = "/api/v1/agents/register"
	AgentNameHeader = "X-Agent-Name"
	AgentIDHeader   = "X-Agent-Id"
)

type agent struct {
	store     *sql.Registry
	hierarchy spec.KeyHierarchy
	topology  spec.Topology
}

// NewServerMux creates the admin API multiplexer with all routes registered.
func NewServerMux(mux *http.ServeMux, store *sql.Registry, hierarchy spec.KeyHierarchy, topology spec.Topology) http.Handler {
	if mux == nil {
		mux = http.NewServeMux()
	}
	a := &agent{hierarchy: hierarchy, store: store, topology: topology}
	mux.HandleFunc("POST "+PathRegister, a.register)
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

	_, err := a.store.Upsert(r.Context(), store.UpsertRegistryQuery{
		Registry: spec.Registry{
			Name:          xAgentName,
			InstanceID:    xAgentID,
			Status:        spec.RegistryStatusHealthy,
			LastHeartbeat: clock.Now(),
		},
	})
	if err != nil {
		log.Printf("failed to upsert registry: %v", err)
		http.Error(w, "failed to upsert registry", http.StatusInternalServerError)
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

func (a *agent) topologySegment(agentName string) (spec.TopologySegment, bool) {
	for _, seg := range a.topology.Segments {
		if seg.Name == agentName {
			return seg, true
		}
	}
	return spec.TopologySegment{}, false
}
