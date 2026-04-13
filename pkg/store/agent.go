package store

import (
	"context"
	"errors"
	"time"

	"github.com/openkcm/krypton/internal/core"
)

var ErrAgentRegistrationNotFound = errors.New("agent registration not found")

type Agent interface {
	Register(ctx context.Context, query RegisterAgentQuery) (RegisterAgentResult, error)
	Get(ctx context.Context, query GetAgentQuery) (GetAgentResult, error)
	UpdateRegistrationStatus(ctx context.Context, query UpdateRegistrationStatusQuery) error
}

type (
	RegisterAgentQuery struct {
		Registration core.AgentRegistration
	}

	RegisterAgentResult struct {
		Registration core.AgentRegistration
	}

	GetAgentQuery struct {
		Name       string
		InstanceID string
	}

	GetAgentResult struct {
		Registration core.AgentRegistration
	}

	UpdateRegistrationStatusQuery struct {
		Name               string
		InstanceID         string
		FromStatus         []core.AgentRegistrationStatus
		ToStatus           core.AgentRegistrationStatus
		HeartbeatThreshold time.Duration
	}
)
