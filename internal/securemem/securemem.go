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

// readonly changes the memory protection of the provided byte slice to read-only, preventing
// any modifications to its contents.
func readonly(data []byte) error {
	// The Mprotect function changes the protection of the memory region to read-only.
	return unix.Mprotect(data, unix.PROT_READ)
}

// readwrite changes the memory protection of the provided byte slice to allow both reading
// and writing, enabling modifications to its contents.
func readwrite(data []byte) error {
	// The Mprotect function changes the protection of the memory region to allow both reading
	// and writing.
	return unix.Mprotect(data, unix.PROT_READ|unix.PROT_WRITE)
}

// unalloc securely deallocates the memory associated with the provided byte slice by first
// zeroing its contents, then unlocking it to allow swapping, and finally unmapping it from
// the process's address space. The function ensures that the memory is securely wiped before
// being released, and it returns any errors encountered during the unlocking and unmapping
// processes.
func unalloc(data []byte) error {
	Zero(data)

	// The Munlock function unlocks the memory region, allowing it to be swapped out if necessary.
	unlockErr := unix.Munlock(data)

	// The Munmap function unmaps the memory region from the process's address space, effectively
	// deallocating it.
	unmapErr := unix.Munmap(data)

	runtime.KeepAlive(data)

	return errors.Join(unlockErr, unmapErr)
}
