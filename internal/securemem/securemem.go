// Package securemem provides utilities for secure memory management. It supports
// allocating memory regions that are locked to physical RAM (preventing swaps to
// disk), protecting memory as read-only or read-write, securely zeroing buffers
// before deallocation, and disabling core dumps to prevent sensitive data from
// being written to disk. Platform-specific implementations handle differences
// between Darwin, Linux, and Windows.
package securemem

import (
	"runtime"
)

// Zero securely wipes the contents of the provided byte slice by setting all bytes to zero.
func Zero(data []byte) {
	for i := range data {
		data[i] = 0
	}

	runtime.KeepAlive(data)
}

// Platform-specific functions that must be implemented in _darwin.go, _linux.go, _windows.go:
// - alloc(size int) ([]byte, error)
// - readonly(data []byte) error
// - readwrite(data []byte) error
// - unalloc(data []byte) error
// - NoDump() error
