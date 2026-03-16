package securemem

import (
	"errors"

	"golang.org/x/sys/unix"
)

// NoDump sets the core file size limit to zero, preventing the process from generating core dumps in case of a crash or other fatal error.
func NoDump() error {
	return unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}

// alloc allocates a memory region of the specified size, locks it to prevent
// swapping, and returns a byte slice that references this memory.
// The memory is allocated using the mmap system call with the MAP_ANON and MAP_PRIVATE flags,
// which means it is not backed by any file and is private to the process.
// Darwin does not support the MADV_DONTDUMP flag, so we skip that step and directly lock the memory after allocation.
func alloc(size int) ([]byte, error) {
	data, err := unix.Mmap(
		-1,                             // no file
		0,                              // offset
		size,                           // length
		unix.PROT_READ|unix.PROT_WRITE, // to have read and write permissions
		unix.MAP_ANON|unix.MAP_PRIVATE, // anonymous mapping, not backed by any file, and private to this process
	)
	if err != nil {
		return nil, err
	}

	err = unix.Mlock(data)
	if err != nil {
		errUnmap := unix.Munmap(data)
		return nil, errors.Join(err, errUnmap)
	}

	return data, nil
}
