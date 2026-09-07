package model

import (
	"uuid"

	"github.com/openkcm/krypton/internal/clock"
)

type Tenant struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Labels    Labels         `json:"labels,omitempty"`
	CreatedAt clock.UnixNano `json:"created_at"`
	UpdatedAt clock.UnixNano `json:"updated_at"`
}

func NewTenant(name string, labels map[string]string) Tenant {
	now := clock.Now()
	return Tenant{
		ID:        uuid.New().String(),
		Name:      name,
		Labels:    labels,
		CreatedAt: now,
		UpdatedAt: now,
	}
}
