// Package config provides local CLI configuration management.
// It handles storing and retrieving user preferences and state.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

var (
	// ErrConfigNotFound is returned when the configuration file does not exist.
	ErrConfigNotFound = errors.New("config not found")
	// ErrConfigNil is returned when attempting to save a nil configuration.
	ErrConfigNil = errors.New("config cannot be nil")
)

const (
	Directory      = ".krypton"
	ConfigFileName = "config.json"
)

// Config represents local CLI configuration.
type Config struct {
	// Tenant stores the currently selected tenant.
	Tenant *TenantSelection `json:"tenant,omitempty"`
}

// TenantSelection stores the selected tenant information.
type TenantSelection struct {
	// ID is the unique identifier of the tenant.
	ID string `json:"id"`
	// Name is the display name of the tenant.
	Name string `json:"name,omitempty"`
}

// Store persists configuration to ~/.krypton/config.json.
type Store struct {
	dirPath    string
	configPath string
}

// NewStore creates a new store that persists configuration to ~/.krypton/config.json.
func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, Directory)

	err = os.MkdirAll(path, 0700)
	if err != nil {
		return nil, err
	}

	return &Store{
		dirPath:    path,
		configPath: filepath.Join(path, ConfigFileName),
	}, nil
}

// Save persists the configuration to the filesystem.
func (s *Store) Save(cfg *Config) error {
	if cfg == nil {
		return ErrConfigNil
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	// Write to a temporary file first, then rename for atomicity
	tmpPath := filepath.Join(s.dirPath, ".config.tmp")
	err = os.WriteFile(tmpPath, data, 0600)
	if err != nil {
		return err
	}

	return os.Rename(tmpPath, s.configPath)
}

// Load retrieves the configuration from the filesystem.
func (s *Store) Load() (*Config, error) {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrConfigNotFound
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Clear removes the configuration file from the filesystem.
func (s *Store) Clear() error {
	err := os.Remove(s.configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
