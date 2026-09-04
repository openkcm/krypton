package store

import (
	"context"
	"encoding/json/v2"
	"os"
	"path/filepath"

	"github.com/openkcm/krypton/pkg/authn"
)

const (
	// Directory is the default directory for storing authentication tokens.
	Directory = ".krypton"
	// TokenFileName is the name of the token file.
	TokenFileName = "token.json"
)

// FS is a filesystem-based implementation of authn.Store.
// It stores tokens as JSON files on disk in the user's home directory under Directory.
type FS struct {
	dirPath   string
	tokenPath string
}

var _ authn.Store = &FS{}

// NewFS creates a new filesystem store that persists tokens to ~/.krypton/token.json.
func NewFS() (*FS, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, Directory)

	err = os.MkdirAll(path, 0700)
	if err != nil {
		return nil, err
	}

	return &FS{
		dirPath:   path,
		tokenPath: filepath.Join(path, TokenFileName),
	}, nil
}

// Store persists the token to the filesystem as a JSON file.
func (f *FS) Store(ctx context.Context, t *authn.Token) error {
	if t == nil {
		return authn.ErrTokenNil
	}

	data, err := json.Marshal(t)
	if err != nil {
		return err
	}

	// Write to a temporary file first, then rename for atomicity
	tmpPath := filepath.Join(f.dirPath, ".tmp")
	err = os.WriteFile(tmpPath, data, 0600)
	if err != nil {
		return err
	}

	return os.Rename(tmpPath, f.tokenPath)
}

// Get retrieves the token from the filesystem.
func (f *FS) Get(ctx context.Context) (*authn.Token, error) {
	data, err := os.ReadFile(f.tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, authn.ErrTokenNotFound
		}
		return nil, err
	}

	var token authn.Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

// Delete removes the token file from the filesystem.
func (f *FS) Delete(ctx context.Context) error {
	err := os.Remove(f.tokenPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
