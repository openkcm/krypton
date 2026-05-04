package securemem

import (
	"errors"
	"log/slog"
	"sync"
)

// MemVault is an in-memory vault that manages multiple named Data instances.
type MemVault struct {
	store map[string]*Data
	mux   sync.RWMutex
}

// ErrVaultDataAlreadyExists is returned by MemVault.Reserve when a vault data
// with the same name already exists in the vault.
var ErrVaultDataAlreadyExists = errors.New("vault data with the same name already exists")

// NewMemVault creates a new MemVault instance with an empty data map.
func NewMemVault() *MemVault {
	return &MemVault{
		store: make(map[string]*Data),
	}
}

// Reserve creates a new Data instance with the given name and size, stores it in the vault, and returns its SecureBytes.
func (v *MemVault) Reserve(name string, size int) (SecureBytes, error) {
	v.mux.Lock()
	defer v.mux.Unlock()

	_, ok := v.store[name]
	if ok {
		slog.Error("vault data with the same name already exists", "name", name)
		return nil, ErrVaultDataAlreadyExists
	}

	data, err := NewData(name, size)
	if err != nil {
		slog.Error("failed to create vault data", "name", name, "size", size, "error", err)
		return nil, err
	}

	v.store[name] = data
	return data.SecureBytes(), nil
}

// Get retrieves the SecureBytes associated with the given name from the vault.
// It returns the SecureBytes and a boolean indicating whether the data was found.
func (v *MemVault) Get(name string) (SecureBytes, bool) {
	v.mux.RLock()
	defer v.mux.RUnlock()

	data, ok := v.store[name]
	if !ok {
		slog.Warn("vault data not found for", "name", name)
		return nil, false
	}

	return data.SecureBytes(), true
}

// Destroy securely destroys the Data instance associated with the given name and removes it from the vault.
func (v *MemVault) Destroy(name string) error {
	v.mux.Lock()
	defer v.mux.Unlock()

	data, ok := v.store[name]
	if !ok {
		slog.Warn("vault data not found for", "name", name)
		return nil
	}

	err := data.Destroy()
	if err != nil {
		slog.Error("failed to destroy vault data for", "name", name, "error", err)
		return err
	}

	delete(v.store, name)

	return nil
}

// DestroyAll securely destroys all Data instances in the vault and clears the vault's store.
func (v *MemVault) DestroyAll() error {
	v.mux.Lock()
	defer v.mux.Unlock()

	errs := make([]error, 0, len(v.store))
	for name, data := range v.store {
		err := data.Destroy()
		if err != nil {
			slog.Error("failed to destroy vault data for", "name", name, "error", err)
			errs = append(errs, err)
			continue
		}
		delete(v.store, name)
	}

	return errors.Join(errs...)
}

// MarkAllReadOnly marks all Data instances in the vault as read-only.
func (v *MemVault) MarkAllReadOnly() error {
	v.mux.Lock()
	defer v.mux.Unlock()

	errs := make([]error, 0, len(v.store))
	for name, data := range v.store {
		err := data.MarkReadOnly()
		if err != nil {
			slog.Error("failed to mark vault data as readonly for", "name", name, "error", err)
			errs = append(errs, err)
			continue
		}
	}

	return errors.Join(errs...)
}
