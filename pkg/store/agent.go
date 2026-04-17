package store

import (
	"context"
	"errors"
	"time"

	"github.com/openkcm/krypton/internal/core"
)

var (
	ErrAgentNotFound     = errors.New("agent registration not found")
	ErrAgentQueryInvalid = errors.New("agent registration query invalid required field")
)

type Agent interface {
	Register(ctx context.Context, q RegisterAgentQuery) (RegisterAgentResult, error)
	Get(ctx context.Context, q GetAgentQuery) (GetAgentResult, error)
	UpdateStatus(ctx context.Context, q UpdateAgentStatusQuery) error
	Delete(ctx context.Context, q DeleteAgentQuery) error
	List(ctx context.Context, q ListAgentQuery) (ListAgentResult, error)
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

	UpdateAgentStatusQuery struct {
		Name               string
		InstanceID         string
		FromStatus         []core.AgentRegistrationStatus
		ToStatus           core.AgentRegistrationStatus
		HeartbeatThreshold time.Duration
	}

	DeleteAgentQuery struct {
		Status             core.AgentRegistrationStatus
		HeartbeatThreshold time.Duration
	}

	ListAgentQuery struct {
		Name string
	}

	ListAgentResult struct {
		Registrations []core.AgentRegistration
	}
)
