package model

import (
	"github.com/google/uuid"

	"github.com/openkcm/krypton/internal/clock"
)

type Labels map[string]string

type Tenant struct {
	ID        string
	Name      string
	Labels    Labels
	CreatedAt int64
	UpdatedAt int64
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
