package config

import "path/filepath"

// NewStoreWithDir creates a new store with a custom directory for testing.
func NewStoreWithDir(dir string) *Store {
	return &Store{
		dirPath:    dir,
		configPath: filepath.Join(dir, ConfigFileName),
	}
}
