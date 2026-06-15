package sqlitevault

import (
	"errors"

	"github.com/openkcm/krypton/internal/vault"
)

// TypeUnsafeMemory identifies an in-memory SQLite vault (unencrypted, for development/testing).
const TypeUnsafeMemory vault.Type = "unsafe-sqlite-memory"

// TypeUnsafe identifies a file-based SQLite vault (unencrypted, for development/testing).
const TypeUnsafe vault.Type = "unsafe-sqlite"

// InMemoryConfig holds configuration for an in-memory SQLite vault.
type InMemoryConfig struct{}

var _ vault.Config = (*InMemoryConfig)(nil)

func (c *InMemoryConfig) ValidateVaultConfig() error {
	return nil
}

// FileConfig holds configuration for a file-based SQLite vault.
type FileConfig struct {
	Path string `yaml:"path"`
}

var _ vault.Config = (*FileConfig)(nil)

func (c *FileConfig) ValidateVaultConfig() error {
	if c.Path == "" {
		return errors.New("path must not be empty")
	}
	return nil
}
