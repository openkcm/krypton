// Package state provides local CLI state management.
// It handles storing and retrieving user state such as the currently selected tenant.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/openkcm/krypton/pkg/authn/store"
)

var (
	// ErrStateNotFound is returned when the state file does not exist.
	ErrStateNotFound = errors.New("state not found")
	// ErrStateNil is returned when attempting to save a nil state.
	ErrStateNil = errors.New("state cannot be nil")
)

const stateFileName = "state.lock"

// State represents local CLI state.
type State struct {
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

// Store persists state to the local filesystem.
type Store struct {
	dirPath   string
	statePath string
}

// NewStore creates a new store that persists state to the user's home directory.
func NewStore() (*Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, store.Directory)

	err = os.MkdirAll(path, 0700)
	if err != nil {
		return nil, err
	}

	return &Store{
		dirPath:   path,
		statePath: filepath.Join(path, stateFileName),
	}, nil
}

// Save persists the state to the filesystem.
func (s *Store) Save(st *State) error {
	if st == nil {
		return ErrStateNil
	}

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}

	// Write to a temporary file first, then rename for atomicity
	tmpPath := filepath.Join(s.dirPath, ".state.tmp")
	err = os.WriteFile(tmpPath, data, 0600)
	if err != nil {
		return err
	}

	return os.Rename(tmpPath, s.statePath)
}

// Load retrieves the state from the filesystem.
func (s *Store) Load() (*State, error) {
	data, err := os.ReadFile(s.statePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrStateNotFound
		}
		return nil, err
	}

	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}

	return &st, nil
}

// Clear removes the state file from the filesystem.
func (s *Store) Clear() error {
	err := os.Remove(s.statePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
