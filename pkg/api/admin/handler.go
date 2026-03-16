package admin

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/openkcm/krypton/pkg/model"
	"github.com/openkcm/krypton/pkg/store"
)

const (
	PathTenants    = "/admin/tenants"
	PathTenantByID = "/admin/tenants/{id}"
)

// NewHandler creates the admin API handler.
func NewHandler(s store.Store) http.Handler {
	mux := http.NewServeMux()
	a := &admin{store: s}
	mux.HandleFunc("POST "+PathTenants, a.createTenant)
	mux.HandleFunc("GET "+PathTenantByID, a.getTenant)
	return mux
}

type admin struct {
	store store.Store
}

type CreateTenantRequest struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
}

type TenantResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels,omitempty"`
	CreatedAt float64           `json:"created_at"`
	UpdatedAt float64           `json:"updated_at"`
}

func (a *admin) createTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	tenant := model.NewTenant(req.Name, req.Labels)
	created, err := a.store.CreateTenant(r.Context(), tenant)
	if err != nil {
		http.Error(w, "failed to create tenant", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(toTenantResponse(created)); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func (a *admin) getTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "tenant id is required", http.StatusBadRequest)
		return
	}

	tenant, err := a.store.GetTenant(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get tenant", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(toTenantResponse(tenant)); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func toTenantResponse(t model.Tenant) TenantResponse {
	return TenantResponse{
		ID:        t.ID,
		Name:      t.Name,
		Labels:    t.Labels,
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}
