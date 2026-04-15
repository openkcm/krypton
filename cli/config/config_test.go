package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/config"
)

func TestStore_SaveAndLoad(t *testing.T) {
	// given
	dir := t.TempDir()
	s := config.NewStoreWithDir(dir)
	cfg := &config.Config{
		Tenant: &config.TenantSelection{
			ID:   "tenant-123",
			Name: "my-tenant",
		},
	}

	// when
	err := s.Save(cfg)

	// then
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, config.ConfigFileName))
	assert.NoError(t, err)

	// when
	got, err := s.Load()

	// then
	assert.NoError(t, err)
	assert.Equal(t, cfg.Tenant.ID, got.Tenant.ID)
	assert.Equal(t, cfg.Tenant.Name, got.Tenant.Name)
}

func TestStore_Save_NilConfig(t *testing.T) {
	// given
	dir := t.TempDir()
	s := config.NewStoreWithDir(dir)

	// when
	err := s.Save(nil)

	// then
	assert.Error(t, err)
	assert.ErrorIs(t, err, config.ErrConfigNil)
}

func TestStore_Save_EmptyConfig(t *testing.T) {
	// given
	dir := t.TempDir()
	s := config.NewStoreWithDir(dir)
	cfg := &config.Config{}

	// when
	err := s.Save(cfg)

	// then
	assert.NoError(t, err)

	// when
	got, err := s.Load()

	// then
	assert.NoError(t, err)
	assert.Nil(t, got.Tenant)
}

func TestStore_Load_NotFound(t *testing.T) {
	// given
	dir := t.TempDir()
	s := config.NewStoreWithDir(dir)

	// when
	_, err := s.Load()

	// then
	assert.ErrorIs(t, err, config.ErrConfigNotFound)
}

func TestStore_Load_InvalidJSON(t *testing.T) {
	// given
	dir := t.TempDir()
	s := config.NewStoreWithDir(dir)
	err := os.WriteFile(filepath.Join(dir, config.ConfigFileName), []byte("invalid json"), 0600)
	assert.NoError(t, err)

	// when
	_, err = s.Load()

	// then
	assert.Error(t, err)
}

func TestStore_Clear(t *testing.T) {
	tests := []struct {
		name      string
		saveFirst bool
	}{
		{
			name:      "clears existing config",
			saveFirst: true,
		},
		{
			name:      "succeeds when config does not exist",
			saveFirst: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			s := config.NewStoreWithDir(dir)

			if tt.saveFirst {
				err := s.Save(&config.Config{
					Tenant: &config.TenantSelection{ID: "test-id"},
				})
				assert.NoError(t, err)
			}

			// when
			err := s.Clear()

			// then
			assert.NoError(t, err)
			_, err = s.Load()
			assert.ErrorIs(t, err, config.ErrConfigNotFound)
		})
	}
}

func TestStore_Save_OverwritesExisting(t *testing.T) {
	// given
	dir := t.TempDir()
	s := config.NewStoreWithDir(dir)

	cfg1 := &config.Config{
		Tenant: &config.TenantSelection{
			ID:   "tenant-1",
			Name: "first-tenant",
		},
	}
	cfg2 := &config.Config{
		Tenant: &config.TenantSelection{
			ID:   "tenant-2",
			Name: "second-tenant",
		},
	}

	// when
	err := s.Save(cfg1)
	assert.NoError(t, err)
	err = s.Save(cfg2)
	assert.NoError(t, err)

	// then
	got, err := s.Load()
	assert.NoError(t, err)
	assert.Equal(t, "tenant-2", got.Tenant.ID)
	assert.Equal(t, "second-tenant", got.Tenant.Name)
}
