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

// NewServerMux creates the admin API multiplexer with all routes registered.
func NewServerMux(s store.Store) http.Handler {
	mux := http.NewServeMux()
	a := &admin{store: s}
	mux.HandleFunc("POST "+PathTenants, a.createTenant)
	mux.HandleFunc("GET "+PathTenantByID, a.getTenant)
	mux.HandleFunc("GET "+PathTenants, a.listTenants)
	return mux
}

type admin struct {
	store store.Store
}

type (
	Tenant struct {
		ID        string       `json:"id"`
		Name      string       `json:"name"`
		Labels    model.Labels `json:"labels,omitempty"`
		UpdatedAt int64        `json:"updated_at"`
		CreatedAt int64        `json:"created_at"`
	}

	CreateTenantRequest struct {
		Name   string       `json:"name"`
		Labels model.Labels `json:"labels,omitempty"`
	}

	CreateTenantResponse struct {
		Tenant Tenant `json:"tenant"`
	}

	GetTenantRequest struct {
		ID string `json:"id"`
	}

	GetTenantResponse struct {
		Tenant Tenant `json:"tenant"`
	}

	ListTenantsRequest struct {
	}

	ListTenantsResponse struct {
		Tenants []Tenant `json:"tenants"`
	}
)

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
	err = json.NewEncoder(w).Encode(toCreateTenantResponse(created))
	if err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func (a *admin) getTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

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
	err = json.NewEncoder(w).Encode(toGetTenantResponse(tenant))
	if err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func (a *admin) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := a.store.ListTenants(r.Context())
	if err != nil {
		http.Error(w, "failed to list tenants", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(toListTenantsResponse(tenants))
	if err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func toCreateTenantResponse(t model.Tenant) CreateTenantResponse {
	return CreateTenantResponse{
		Tenant: Tenant{
			ID:        t.ID,
			Name:      t.Name,
			Labels:    t.Labels,
			CreatedAt: t.CreatedAt,
			UpdatedAt: t.UpdatedAt,
		},
	}
}

func toGetTenantResponse(t model.Tenant) GetTenantResponse {
	return GetTenantResponse{
		Tenant: Tenant{
			ID:        t.ID,
			Name:      t.Name,
			Labels:    t.Labels,
			CreatedAt: t.CreatedAt,
			UpdatedAt: t.UpdatedAt,
		},
	}
}

func toListTenantsResponse(tenants []model.Tenant) ListTenantsResponse {
	resp := ListTenantsResponse{
		Tenants: make([]Tenant, len(tenants)),
	}
	for i, t := range tenants {
		resp.Tenants[i] = Tenant{
			ID:        t.ID,
			Name:      t.Name,
			Labels:    t.Labels,
			CreatedAt: t.CreatedAt,
			UpdatedAt: t.UpdatedAt,
		}
	}
	return resp
}
