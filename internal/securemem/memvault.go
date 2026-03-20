package securemem

import (
	"errors"
	"log/slog"
	"sync"
)

// MemVault is an in-memory vault that manages multiple named Data instances.
type MemVault struct {
	store      map[string]*Data
	mux        sync.RWMutex
	isReadOnly bool
}

// ErrVaultDataAlreadyExists is returned by MemVault.Reserve when a vault data
// with the same name already exists in the vault.
var ErrVaultDataAlreadyExists = errors.New("vault data with the same name already exists")

// ErrVaultReadOnly is returned by MemVault.Reserve when the vault is marked as read-only.
var ErrVaultReadOnly = errors.New("vault is read-only")

// NewMemVault creates a new MemVault instance with an empty data map.
func NewMemVault() *MemVault {
	return &MemVault{
		store: make(map[string]*Data),
	}
}

// Reserve creates a new Data instance with the given name and size, and stores it in the vault.
func (v *MemVault) Reserve(name string, size int) ([]byte, error) {
	v.mux.Lock()
	defer v.mux.Unlock()

	if v.isReadOnly {
		return nil, ErrVaultReadOnly
	}

	_, ok := v.store[name]
	if ok {
		return nil, ErrVaultDataAlreadyExists
	}

	data, err := NewData(name, size)
	if err != nil {
		return nil, err
	}

	v.store[name] = data
	return data.Bytes(), nil
}

// Get retrieves the byte slice associated with the given name from the vault.
func (v *MemVault) Get(name string) ([]byte, bool) {
	v.mux.RLock()
	defer v.mux.RUnlock()

	data, ok := v.store[name]
	if !ok {
		return nil, false
	}

	return data.Bytes(), true
}

// Destroy securely destroys the Data instance associated with the given name and removes it from the vault.
func (v *MemVault) Destroy(name string) error {
	v.mux.Lock()
	defer v.mux.Unlock()

	data, ok := v.store[name]
	if !ok {
		return nil
	}

	err := data.Destroy()
	if err != nil {
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

	err := errors.Join(errs...)
	if err == nil {
		v.isReadOnly = true
	}

	return err
}
