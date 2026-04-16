package state_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/cli/state"
)

func TestStore_SaveAndLoad(t *testing.T) {
	// given
	dir := t.TempDir()
	s := state.NewStoreWithDir(dir)
	st := &state.State{
		Tenant: &state.TenantSelection{
			ID:   "tenant-123",
			Name: "my-tenant",
		},
	}

	// when
	err := s.Save(st)

	// then
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, state.StateFileName))
	assert.NoError(t, err)

	// when
	got, err := s.Load()

	// then
	assert.NoError(t, err)
	assert.Equal(t, st.Tenant.ID, got.Tenant.ID)
	assert.Equal(t, st.Tenant.Name, got.Tenant.Name)
}

func TestStore_Save_NilState(t *testing.T) {
	// given
	dir := t.TempDir()
	s := state.NewStoreWithDir(dir)

	// when
	err := s.Save(nil)

	// then
	assert.Error(t, err)
	assert.ErrorIs(t, err, state.ErrStateNil)
}

func TestStore_Save_EmptyState(t *testing.T) {
	// given
	dir := t.TempDir()
	s := state.NewStoreWithDir(dir)
	st := &state.State{}

	// when
	err := s.Save(st)

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
	s := state.NewStoreWithDir(dir)

	// when
	_, err := s.Load()

	// then
	assert.ErrorIs(t, err, state.ErrStateNotFound)
}

func TestStore_Load_InvalidJSON(t *testing.T) {
	// given
	dir := t.TempDir()
	s := state.NewStoreWithDir(dir)
	err := os.WriteFile(filepath.Join(dir, state.StateFileName), []byte("invalid json"), 0600)
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
			name:      "clears existing state",
			saveFirst: true,
		},
		{
			name:      "succeeds when state does not exist",
			saveFirst: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			s := state.NewStoreWithDir(dir)

			if tt.saveFirst {
				err := s.Save(&state.State{
					Tenant: &state.TenantSelection{ID: "test-id"},
				})
				assert.NoError(t, err)
			}

			// when
			err := s.Clear()

			// then
			assert.NoError(t, err)
			_, err = s.Load()
			assert.ErrorIs(t, err, state.ErrStateNotFound)
		})
	}
}

func TestStore_Save_OverwritesExisting(t *testing.T) {
	// given
	dir := t.TempDir()
	s := state.NewStoreWithDir(dir)

	st1 := &state.State{
		Tenant: &state.TenantSelection{
			ID:   "tenant-1",
			Name: "first-tenant",
		},
	}
	st2 := &state.State{
		Tenant: &state.TenantSelection{
			ID:   "tenant-2",
			Name: "second-tenant",
		},
	}

	// when
	err := s.Save(st1)
	assert.NoError(t, err)
	err = s.Save(st2)
	assert.NoError(t, err)

	// then
	got, err := s.Load()
	assert.NoError(t, err)
	assert.Equal(t, "tenant-2", got.Tenant.ID)
	assert.Equal(t, "second-tenant", got.Tenant.Name)
}
