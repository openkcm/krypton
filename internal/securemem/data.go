package securemem

import (
	"errors"
	"sync"
)

// Data is a named, secure memory region backed by mmap'd anonymous memory
// that is locked to physical RAM to prevent swapping. It supports toggling the
// underlying memory between read-write and read-only modes via mprotect, and
// provides a Destroy method that securely zeroes the buffer, unlocks, and unmaps
// the memory.
type Data struct {
	name       string
	data       []byte
	isReadOnly bool
	mux        sync.RWMutex
}

// ErrInvalidSize is returned by NewData when the requested allocation
// size is zero or negative.
var ErrInvalidSize = errors.New("invalid size: must be greater than 0")

// NewData allocates a new secure memory region of the given size and
// associates it with the provided name. The underlying memory is mmap'd and
// locked to prevent swapping. It returns ErrInvalidSize if size is less than
// or equal to zero.
func NewData(name string, size int) (*Data, error) {
	if size <= 0 {
		return nil, ErrInvalidSize
	}

	aBytes, err := alloc(size)
	if err != nil {
		return nil, err
	}

	return &Data{
		name: name,
		data: aBytes,
	}, nil
}

// Data returns the underlying byte slice of the secure memory region. If the
// vault has been destroyed, it returns nil. The returned slice points directly
// to the locked memory; callers must not hold references after Destroy is called.
func (m *Data) Data() []byte {
	m.mux.RLock()
	defer m.mux.RUnlock()

	if m.data == nil {
		return nil
	}

	return m.data
}

// Destroy securely wipes the memory region, unlocks it, and unmaps it from the
// process address space. If the vault is currently read-only, it is first
// switched back to read-write before zeroing. Subsequent calls to Destroy are
// safe and return nil. After Destroy returns, Data will return nil.
func (m *Data) Destroy() error {
	m.mux.Lock()
	defer m.mux.Unlock()

	if m.data == nil {
		return nil
	}

	if m.isReadOnly {
		err := readwrite(m.data)
		if err != nil {
			return err
		}
		m.isReadOnly = false
	}

	defer func() {
		m.data = nil
	}()

	return unalloc(m.data)
}

// MarkReadOnly sets the memory protection of the underlying buffer to read-only,
// preventing any further writes. This operation is idempotent; calling it on an
// already read-only vault returns nil without error. If the vault has been
// destroyed, it returns nil.
// Once `MarkReadOnly()` is called, the only way to make data writable again is
// `Destroy()`.
func (m *Data) MarkReadOnly() error {
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

// Name returns the human-readable name associated with this secure memory region.
func (m *Data) Name() string {
	return m.name
}

// IsReadOnly reports whether the underlying memory region is currently protected
// as read-only.
func (m *Data) IsReadOnly() bool {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return m.isReadOnly
}
