package state

import "path/filepath"

// StateFileName is exported for testing.
const StateFileName = stateFileName

// NewStoreWithDir creates a new store with a custom directory for testing.
func NewStoreWithDir(dir string) *Store {
	return &Store{
		dirPath:   dir,
		statePath: filepath.Join(dir, stateFileName),
	}
}
