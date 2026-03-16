package securemem

import (
	"errors"
	"log/slog"
	"sync"
)

type MemVaultData struct {
	name       string
	data       []byte
	isReadOnly bool
	mux        sync.RWMutex
}

var ErrInvalidSize = errors.New("invalid size: must be greater than 0")

func NewMemVaultData(name string, size int) (*MemVaultData, error) {
	if size <= 0 {
		return nil, ErrInvalidSize
	}

	aBytes, err := alloc(size)
	if err != nil {
		return nil, err
	}

	return &MemVaultData{
		name: name,
		data: aBytes,
	}, nil
}

func (m *MemVaultData) Data() []byte {
	m.mux.RLock()
	defer m.mux.RUnlock()

	if m.data == nil {
		return nil
	}

	return m.data
}

func (m *MemVaultData) Destroy() error {
	m.mux.Lock()
	defer m.mux.Unlock()

	if m.data == nil {
		return nil
	}

	defer func() {
		m.data = nil
	}()

	if m.isReadOnly {
		err := readwrite(m.data)
		if err != nil {
			slog.Error("failed to change vault data to read-write before unallocating for", "name", m.name, "error", err)
		}
		m.isReadOnly = false
	}

	return unalloc(m.data)
}

func (m *MemVaultData) MarkReadOnly() error {
	m.mux.Lock()
	defer m.mux.Unlock()

	if m.data == nil {
		return nil
	}
	if m.isReadOnly {
		return nil
	}

	err := readonly(m.data)
	m.isReadOnly = err == nil
	return err
}

func (m *MemVaultData) Name() string {
	return m.name
}

func (m *MemVaultData) IsReadOnly() bool {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return m.isReadOnly
}
