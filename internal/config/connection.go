package config

import (
	"errors"
	"fmt"
	"slices"
)

// ConnectionConfigs is a list of agent connection configurations.
type ConnectionConfigs []ConnectionConfig

// ConnectionConfig holds the name and address for connecting to a specific agent.
type ConnectionConfig struct {
	Name    string  `yaml:"name"`
	Address Address `yaml:"address"`
}

var (
	ErrInvalidConnectionConfig = errors.New("connection config is invalid")
	ErrNoConnectionConfig      = errors.New("connection config not found")
)

// ByNames returns the ConnectionConfigs matching the given agent names, or
// ErrNoConnectionConfig if any requested name has no corresponding entry.
func (cs ConnectionConfigs) ByNames(agentNames ...string) (ConnectionConfigs, error) {
	if len(agentNames) == 0 {
		return nil, fmt.Errorf("%w: no agent names provided", ErrNoConnectionConfig)
	}
	filters := make(map[string]struct{}, len(agentNames))
	for _, an := range agentNames {
		filters[an] = struct{}{}
	}
	res := make(ConnectionConfigs, 0, len(agentNames))
	for _, c := range cs {
		if _, ok := filters[c.Name]; ok {
			res = append(res, c)
			delete(filters, c.Name)
		}
	}
	if len(filters) != 0 {
		missing := make([]string, 0, len(filters))
		for name := range filters {
			missing = append(missing, name)
		}
		slices.Sort(missing)
		return nil, fmt.Errorf("%w: for agents %q", ErrNoConnectionConfig, missing)
	}
	return res, nil
}

// Validate checks that all connection configs are well-formed and that every
// topology segment has a corresponding connection entry.
func (cs ConnectionConfigs) Validate(rc *RootConfig) error {
	if rc == nil {
		return fmt.Errorf("%w: root config is nil", ErrInvalidConnectionConfig)
	}

	seen := make(map[string]struct{}, len(cs)+1)
	for _, c := range cs {
		if err := c.validate(); err != nil {
			return err
		}
		if _, ok := seen[c.Name]; ok {
			return fmt.Errorf("%w: duplicate name %q", ErrInvalidConnectionConfig, c.Name)
		}
		seen[c.Name] = struct{}{}
	}

	for _, seg := range rc.Topology.Segments {
		if _, ok := seen[seg.Name]; !ok {
			return fmt.Errorf("%w: no connection config for segment %q", ErrInvalidConnectionConfig, seg.Name)
		}
	}
	if _, ok := seen[rc.Name]; !ok {
		return fmt.Errorf("%w: no connection config for root %q", ErrInvalidConnectionConfig, rc.Name)
	}
	return nil
}

func (c *ConnectionConfig) validate() error {
	if c.Name == "" {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidConnectionConfig)
	}
	// only gRPC is currently supported
	if err := c.Address.Validate(); err != nil {
		return fmt.Errorf("%w: address validation failed for %q: %w", ErrInvalidConnectionConfig, c.Name, err)
	}
	return nil
}
