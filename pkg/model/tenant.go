package model

import (
	"github.com/google/uuid"

	"github.com/openkcm/krypton/internal/clock"
)

type Tenant struct {
	ID        string
	Name      string
	Labels    map[string]string
	CreatedAt float64
	UpdatedAt float64
}

func NewTenant(name string, labels map[string]string) Tenant {
	now := clock.NowUTC()
	return Tenant{
		ID:        uuid.NewString(),
		Name:      name,
		Labels:    labels,
		CreatedAt: now,
		UpdatedAt: now,
	}
}
