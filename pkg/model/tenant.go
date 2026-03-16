package model

import (
	"time"

	"github.com/google/uuid"

	"github.com/openkcm/krypton/internal/clock"
)

type Labels map[string]string

type Tenant struct {
	ID        string
	Name      string
	Labels    Labels
	CreatedAt time.Time
	UpdatedAt time.Time
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
