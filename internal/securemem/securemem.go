// Package securemem provides utilities for secure memory management. It supports
// allocating memory regions that are locked to physical RAM (preventing swaps to
// disk), protecting memory as read-only or read-write, securely zeroing buffers
// before deallocation, and disabling core dumps to prevent sensitive data from
// being written to disk. Platform-specific implementations handle differences
// between Darwin and Linux (e.g. MADV_DONTDUMP on Linux, PR_SET_DUMPABLE).
package securemem

import (
	"errors"
	"runtime"

	"golang.org/x/sys/unix"
)

// Zero securely wipes the contents of the provided byte slice by setting all bytes to zero.
func Zero(data []byte) {
	for i := range data {
		data[i] = 0
	}

	runtime.KeepAlive(data)
}

// readonly changes the memory protection of the provided byte slice to
// read-only, preventing any modifications to its contents.
func readonly(data []byte) error {
	return unix.Mprotect(data, unix.PROT_READ)
}

// readwrite changes the memory protection of the provided byte slice to
// allow both reading and writing, enabling modifications to its contents.
func readwrite(data []byte) error {
	return unix.Mprotect(data, unix.PROT_READ|unix.PROT_WRITE)
}

// unalloc securely deallocates the memory associated with the provided byte slice by first zeroing its contents,
// then unlocking it to allow swapping, and finally unmapping it from the process's address space.
// The function ensures that the memory is securely wiped before being released, and it returns any
// errors encountered during the unlocking and unmapping processes.
func unalloc(data []byte) error {
	Zero(data)

	unlockErr := unix.Munlock(data)
	unmapErr := unix.Munmap(data)

	runtime.KeepAlive(data)

	return errors.Join(unlockErr, unmapErr)
}
