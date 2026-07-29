package securemem

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
)

const Redacted = "<<REDACTED>>"

// SecureBytes is a byte slice that implements various stringer and marshaler interfaces to prevent
// accidental logging or printing of sensitive data. It always returns a redacted string representation,
// regardless of the actual contents of the byte slice.
type SecureBytes []byte

// Data is a named, secure memory region backed by mmap'd anonymous memory
// that is locked to physical RAM to prevent swapping. It supports toggling the
// underlying memory between read-write and read-only modes via mprotect, and
// provides a Destroy method that securely zeroes the buffer, unlocks, and unmaps
// the memory.
type Data struct {
	name       string
	data       SecureBytes
	isReadOnly bool
	mux        sync.RWMutex
	cleanup    runtime.Cleanup
}

type dataCleanupRef struct {
	name string
	data SecureBytes
}

var (
	// This is to ensure that data secret is not accidentally logged or printed in any way.
	// Ensure covers %s, %v, %+v
	_ fmt.Stringer = (*Data)(nil)
	_ fmt.Stringer = (SecureBytes)(nil)
	// covers %#v
	_ fmt.GoStringer = (*Data)(nil)
	_ fmt.GoStringer = (SecureBytes)(nil)
	// covers slog
	_ slog.LogValuer = (*Data)(nil)
	_ slog.LogValuer = (SecureBytes)(nil)
	// covers structured loggers
	_ encoding.TextMarshaler = (*Data)(nil)
	_ encoding.TextMarshaler = (SecureBytes)(nil)
	// covers JSON serialization
	_ json.Marshaler = (*Data)(nil)
	_ json.Marshaler = (SecureBytes)(nil)
)

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

	b, err := alloc(size)
	if err != nil {
		return nil, err
	}

	d := &Data{
		name: name,
		data: b,
	}

	d.cleanup = runtime.AddCleanup(d, func(m *dataCleanupRef) {
		slog.Debug("securemem: cleanup started")
		err := m.Destroy()
		if err != nil {
			slog.Error("securemem: failed to destroy secure memory region", "error", err)
		}
		slog.Debug("securemem: cleanup finished")
	}, &dataCleanupRef{name: d.name, data: d.data})

	return d, nil
}

// SecureBytes returns the underlying byte slice of the secure memory region. If the
// vault has been destroyed, it returns nil. The returned slice points directly
// to the locked memory; callers must not hold references after Destroy is called.
func (m *Data) SecureBytes() SecureBytes {
	m.mux.RLock()
	defer m.mux.RUnlock()

	if m.data == nil {
		return nil
	}

	return m.data
}

// Destroy securely wipes, unlocks, and unmaps the memory region; afterwards
// SecureBytes returns nil. Safe on a nil receiver and after a prior Destroy.
// Failures are logged.
func (m *Data) Destroy() error {
	if m == nil {
		return nil
	}

	m.mux.Lock()
	defer m.mux.Unlock()

	slog.Debug("securemem: destroy started", "name", m.name)

	if m.data == nil {
		slog.Debug("securemem: destroy skipped, already destroyed", "name", m.name)
		return nil
	}

	if m.isReadOnly {
		err := readwrite(m.data)
		if err != nil {
			slog.Error("securemem: destroy marking readwrite failed", "name", m.name, "error", err)
			return err
		}
		m.isReadOnly = false
	}

	defer func() {
		m.data = nil
		m.cleanup.Stop()
	}()

	err := unalloc(m.data)
	if err != nil {
		slog.Error("securemem: destroy failed", "name", m.name, "error", err)
	} else {
		slog.Debug("securemem: destroy finished", "name", m.name)
	}

	return err
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

// String implements [fmt.Stringer].
func (m *Data) String() string {
	return fmt.Sprintf(`{"Name":"%s", "Value":"%s"}`, m.name, m.data.String())
}

// GoString implements [fmt.GoStringer].
func (m *Data) GoString() string {
	return m.String()
}

// LogValue implements [slog.LogValuer].
func (m *Data) LogValue() slog.Value {
	return slog.StringValue(m.String())
}

// MarshalJSON implements [json.Marshaler].
func (m *Data) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.String())
}

// MarshalText implements [encoding.TextMarshaler].
func (m *Data) MarshalText() (text []byte, err error) {
	return []byte(m.String()), nil
}

// String implements [fmt.Stringer].
func (s SecureBytes) String() string {
	return Redacted
}

// GoString implements [fmt.GoStringer].
func (s SecureBytes) GoString() string {
	return Redacted
}

// LogValue implements [slog.LogValuer].
func (s SecureBytes) LogValue() slog.Value {
	return slog.StringValue(Redacted)
}

// MarshalText implements [encoding.TextMarshaler].
func (s SecureBytes) MarshalText() (text []byte, err error) {
	return []byte(Redacted), nil
}

// MarshalJSON implements [json.Marshaler].
func (s SecureBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(Redacted)
}

// Destroy securely wipes and unmaps the memory region referenced by this cleanup ref.
// It creates a temporary Data with isReadOnly=true so that Destroy() always calls
// readwrite() (mprotect) first — this acts as a safe guard that returns ENOMEM if the
// memory was already unmapped by a prior Destroy() call, preventing Zero() from writing
// to invalid memory (which would SIGSEGV).
func (m *dataCleanupRef) Destroy() error {
	data := &Data{data: m.data, isReadOnly: true, name: m.name}
	return data.Destroy()
}
