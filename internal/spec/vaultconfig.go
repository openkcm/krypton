package spec

import (
	"errors"
	"fmt"
)

// ErrVaultConfigInvalid is returned when a vault configuration is invalid.
var ErrVaultConfigInvalid = errors.New("invalid vault config")

// VaultConfig is an interface that all vault configuration types must implement.
type VaultConfig interface {
	IsValidVaultConfig() error
}

// InMemoryConfig is a vault configuration for an in-memory vault.
type InMemoryConfig struct {
	Prefix string
}

// OpenBAOConfig is a vault configuration for an OpenBAO vault.
type OpenBAOConfig struct {
	ClusterAddress string
}

var (
	_ VaultConfig = (*InMemoryConfig)(nil)
	_ VaultConfig = (*OpenBAOConfig)(nil)
)

// IsValidVaultConfig checks if the InMemoryConfig is valid.
func (i *InMemoryConfig) IsValidVaultConfig() error {
	if i.Prefix == "" {
		return fmt.Errorf("prefix cannot be empty: %w", ErrVaultConfigInvalid)
	}
	return nil
}

// IsValidVaultConfig checks if the OpenBAOConfig is valid.
func (o *OpenBAOConfig) IsValidVaultConfig() error {
	if o.ClusterAddress == "" {
		return fmt.Errorf("cluster address cannot be empty: %w", ErrVaultConfigInvalid)
	}
	return nil
}
