package agents

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/openkcm/krypton/internal/model"
	"github.com/openkcm/krypton/internal/models"
)

type (
	RegisterRequest  struct{}
	RegisterResponse struct {
		Config model.AgentConfig `json:"config"`
	}
)

const (
	PathRegister    = "/api/v1/agents/register"
	AgentNameHeader = "X-Agent-Name"
)

type agent struct {
	hierarchy model.KeyHierarchy
	topology  models.Topology
}

// NewServerMux creates the admin API multiplexer with all routes registered.
func NewServerMux(mux *http.ServeMux, hierarchy model.KeyHierarchy, topology models.Topology) http.Handler {
	if mux == nil {
		mux = http.NewServeMux()
	}
	a := &agent{hierarchy: hierarchy, topology: topology}
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

	seg, ok := a.topologySegment(xAgentName)
	if !ok {
		log.Printf("agent '%s' not found in topology", xAgentName)
		http.Error(w, "agent not found in topology", http.StatusNotFound)
		return
	}

	cfg := model.NewAgentConfig(a.hierarchy, seg)

	err := json.NewEncoder(w).Encode(RegisterResponse{Config: cfg})
	if err != nil {
		log.Printf("failed to encode response: %v", err)
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (a *agent) topologySegment(agentName string) (models.TopologySegment, bool) {
	for _, seg := range a.topology.Segments {
		if seg.Name == agentName {
			return seg, true
		}
	}
	return models.TopologySegment{}, false
}
