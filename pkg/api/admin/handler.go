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
func NewServerMux(s store.Tenant) http.Handler {
	mux := http.NewServeMux()
	a := &admin{store: s}
	mux.HandleFunc("POST "+PathTenants, a.createTenant)
	mux.HandleFunc("GET "+PathTenants, a.listTenants)
	mux.HandleFunc("GET "+PathTenantByID, a.getTenant)
	return mux
}

type admin struct {
	store store.Tenant
}

type (
	CreateTenantRequest struct {
		Name   string       `json:"name"`
		Labels model.Labels `json:"labels,omitempty"`
	}

	CreateTenantResponse struct {
		Tenant model.Tenant `json:"tenant"`
	}

	GetTenantRequest struct {
		ID string `json:"id"`
	}

	GetTenantResponse struct {
		Tenant model.Tenant `json:"tenant"`
	}

	ListTenantsRequest struct{}

	ListTenantsResponse struct {
		Tenants []model.Tenant `json:"tenants"`
	}
)

func (a *admin) createTenant(w http.ResponseWriter, r *http.Request) {
	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	tenant := model.NewTenant(req.Name, req.Labels)
	result, err := a.store.CreateTenant(r.Context(), store.CreateTenantQuery{
		Tenant: tenant,
	})
	if err != nil {
		http.Error(w, "failed to create tenant", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(CreateTenantResponse{
		Tenant: result.Tenant,
	})
	if err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func (a *admin) getTenant(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	result, err := a.store.GetTenant(r.Context(), store.GetTenantQuery{
		ID: id,
	})
	if err != nil {
		if errors.Is(err, store.ErrTenantNotFound) {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to get tenant", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(GetTenantResponse{
		Tenant: result.Tenant,
	})
	if err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}

func (a *admin) listTenants(w http.ResponseWriter, r *http.Request) {
	result, err := a.store.ListTenants(r.Context(), store.ListTenantsQuery{})
	if err != nil {
		http.Error(w, "failed to list tenants", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(ListTenantsResponse{
		Tenants: result.Tenants,
	})
	if err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}
