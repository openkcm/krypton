package model

import (
	"github.com/google/uuid"

	"github.com/openkcm/krypton/internal/clock"
)

type Labels map[string]string

type Tenant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Labels    Labels `json:"labels,omitempty"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

func NewTenant(name string, labels map[string]string) Tenant {
	now := clock.NowUnixUTC()
	return Tenant{
		ID:        uuid.NewString(),
		Name:      name,
		Labels:    labels,
		CreatedAt: now,
		UpdatedAt: now,
	}
}
