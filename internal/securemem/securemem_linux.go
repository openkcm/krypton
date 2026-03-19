package securemem

import (
	"errors"

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
