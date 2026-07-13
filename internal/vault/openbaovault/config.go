package openbaovault

import (
	"errors"

	"github.com/openkcm/krypton/internal/vault"
)

// TypeOpenBao is the vault type identifier for the OpenBao vault implementation.
const TypeOpenBao vault.Type = "openbao"

// Config holds the configuration for the OpenBao vault implementation.
type Config struct {
	Address string `yaml:"address"`
}

var _ vault.Config = (*Config)(nil)

// ValidateVaultConfig checks that the OpenBao vault configuration is valid.
func (c *Config) ValidateVaultConfig() error {
	if c.Address == "" {
		return errors.New("address is required")
	}
	return nil
}
