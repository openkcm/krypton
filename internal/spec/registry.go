package spec

import "github.com/openkcm/krypton/internal/clock"

// RegistryStatus represents the status of a registry entry.
type RegistryStatus string

// RegistryStatusHealthy indicates that the registry is active and healthy.
const (
	RegistryStatusHealthy   RegistryStatus = "healthy"
	RegistryStatusUnhealthy RegistryStatus = "unhealthy"
)

// Registry entries are used to track the status of agents and their heartbeats.
type Registry struct {
	Name          string
	InstanceID    string
	Status        RegistryStatus
	LastHeartbeat clock.UnixNano
	CreatedAt     clock.UnixNano
	UpdatedAt     clock.UnixNano
}
