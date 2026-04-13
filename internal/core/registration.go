package core

import "github.com/openkcm/krypton/internal/clock"

// AgentRegistrationStatus represents the status of a registration entry.
type AgentRegistrationStatus string

const (
	// AgentRegistrationStatusHealthy indicates that the registration is active and healthy.
	AgentRegistrationStatusHealthy AgentRegistrationStatus = "healthy"

	// AgentRegistrationStatusUnhealthy indicates that the registration is active but unhealthy.
	AgentRegistrationStatusUnhealthy AgentRegistrationStatus = "unhealthy"
)

// AgentRegistration entries are used to track the status of agents and their heartbeats.
type AgentRegistration struct {
	Name          string
	InstanceID    string
	Status        AgentRegistrationStatus
	LastHeartbeat clock.UnixNano
	CreatedAt     clock.UnixNano
	UpdatedAt     clock.UnixNano
}
