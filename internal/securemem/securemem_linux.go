//go:build linux

package securemem

import (
	"errors"
	"runtime"

	"golang.org/x/sys/unix"
)

// NoDump sets the core file size limit to zero and marks the process as non-dumpable,
// preventing the process from generating core dumps in case of a crash or other fatal error.
func NoDump() error {
	// Setrlimit is used to set the core file size limit to zero, which prevents the process
	// from generating core dumps.
	err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	if err != nil {
		return err
	}

	// Prctl is used to set the process as non-dumpable, which further ensures that core
	// dumps are not generated for this process.
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// alloc allocates a memory region of the specified size, locks it to prevent swapping,
// and returns a byte slice that references this memory. The memory is allocated using the
// mmap system call with the MAP_ANON and MAP_PRIVATE flags, which means it is not backed
// by any file and is private to the process. Additionally, it uses the MADV_DONTDUMP flag
// to prevent the memory from being included in core dumps, enhancing security.
func alloc(size int) ([]byte, error) {
	// Mmap is used to allocate a memory region of the specified size.
	// The parameters specify that the memory should be readable and writable,
	// and that it should be an anonymous mapping that is private to the process.
	data, err := unix.Mmap(
		-1,                             // no file
		0,                              // offset
		size,                           // length
		unix.PROT_READ|unix.PROT_WRITE, // to have read and write permissions
		unix.MAP_ANON|unix.MAP_PRIVATE, // anonymous mapping and private to this process
	)
	if err != nil {
		return nil, err
	}

	// Madvise is used to set the MADV_DONTDUMP flag on the allocated memory region, which
	// prevents it from being included in core dumps.
	err = unix.Madvise(data, unix.MADV_DONTDUMP)
	if err != nil {
		errUnmap := unix.Munmap(data)
		return nil, errors.Join(err, errUnmap)
	}

	// Mlock is used to lock the allocated memory region, preventing it from being swapped out
	// to disk.
	err = unix.Mlock(data)
	if err != nil {
		// even if Mlock fails, we should still unmap the memory to avoid leaks
		errUnmap := unix.Munmap(data)
		return nil, errors.Join(err, errUnmap)
	}

	return data, nil
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
