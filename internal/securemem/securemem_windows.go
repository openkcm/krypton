//go:build windows

package securemem

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var noDumpOnce sync.Once

// NoDump attempts to prevent crash dumps on Windows by configuring error handling mode.
// Note: This provides limited protection compared to Unix systems. Full crash dump prevention
// on Windows would require additional registry settings and Windows Error Reporting (WER) configuration.
func NoDump() error {
	// Log a warning once about the limitation
	noDumpOnce.Do(func() {
		slog.Warn("securemem: NoDump() provides limited crash dump protection on Windows",
			"note", "Full protection requires additional WER configuration and registry settings")
	})

	// SetErrorMode configures the process to suppress error dialogs and prevent some types of dumps.
	// This is not as comprehensive as Unix RLIMIT_CORE + PR_SET_DUMPABLE but provides some protection.
	windows.SetErrorMode(windows.SEM_NOGPFAULTERRORBOX | windows.SEM_FAILCRITICALERRORS)

	return nil
}

// alloc allocates a memory region of the specified size using VirtualAlloc, locks it to prevent
// paging to disk using VirtualLock, and returns a byte slice that references this memory.
// Windows uses VirtualAlloc with PAGE_READWRITE for allocation and VirtualLock to prevent paging.
func alloc(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid size: %d", size)
	}

	// VirtualAlloc allocates memory with MEM_COMMIT | MEM_RESERVE flags and PAGE_READWRITE protection.
	// This is the Windows equivalent of mmap with MAP_ANON | MAP_PRIVATE and PROT_READ | PROT_WRITE.
	addr, err := windows.VirtualAlloc(
		0,                                 // lpAddress (let system choose address)
		uintptr(size),                     // dwSize
		windows.MEM_COMMIT|windows.MEM_RESERVE, // flAllocationType
		windows.PAGE_READWRITE,            // flProtect
	)
	if err != nil {
		return nil, fmt.Errorf("VirtualAlloc failed: %w", err)
	}

	// Convert the allocated memory address to a byte slice.
	// This conversion from uintptr to unsafe.Pointer is safe because:
	// 1. VirtualAlloc returns memory outside the Go heap that won't be moved by GC
	// 2. We immediately convert to a slice which keeps the memory alive
	// 3. The addr uintptr is used in the same expression, not stored and reused later
	//
	//nolint:unsafeptr // See explanation above - this is the correct pattern for VirtualAlloc
	data := unsafe.Slice((*byte)(unsafe.Pointer(addr)), size)

	// VirtualLock locks the allocated memory region, preventing it from being paged to disk.
	// This is the Windows equivalent of mlock.
	err = windows.VirtualLock(addr, uintptr(size))
	if err != nil {
		// If VirtualLock fails, free the allocated memory to avoid leaks
		windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
		return nil, fmt.Errorf("VirtualLock failed: %w", err)
	}

	return data, nil
}

// readonly changes the memory protection of the provided byte slice to read-only,
// preventing any modifications to its contents. Uses VirtualProtect to set PAGE_READONLY.
func readonly(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	var oldProtect uint32
	err := windows.VirtualProtect(
		uintptr(unsafe.Pointer(&data[0])), // lpAddress
		uintptr(len(data)),                // dwSize
		windows.PAGE_READONLY,             // flNewProtect
		&oldProtect,                       // lpflOldProtect
	)
	if err != nil {
		return fmt.Errorf("VirtualProtect (readonly) failed: %w", err)
	}

	return nil
}

// readwrite changes the memory protection of the provided byte slice to allow both
// reading and writing. Uses VirtualProtect to set PAGE_READWRITE.
func readwrite(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	var oldProtect uint32
	err := windows.VirtualProtect(
		uintptr(unsafe.Pointer(&data[0])), // lpAddress
		uintptr(len(data)),                // dwSize
		windows.PAGE_READWRITE,            // flNewProtect
		&oldProtect,                       // lpflOldProtect
	)
	if err != nil {
		return fmt.Errorf("VirtualProtect (readwrite) failed: %w", err)
	}

	return nil
}

// unalloc securely deallocates the memory associated with the provided byte slice by first
// zeroing its contents, then unlocking it to allow paging, and finally freeing it.
// The function ensures that the memory is securely wiped before being released.
func unalloc(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	Zero(data)

	addr := uintptr(unsafe.Pointer(&data[0]))
	size := uintptr(len(data))

	// VirtualUnlock unlocks the memory region, allowing it to be paged out if necessary.
	// This is the Windows equivalent of munlock.
	unlockErr := windows.VirtualUnlock(addr, size)

	// VirtualFree frees the memory region from the process's address space.
	// This is the Windows equivalent of munmap.
	// MEM_RELEASE requires dwSize to be 0 and releases the entire region allocated by VirtualAlloc.
	freeErr := windows.VirtualFree(addr, 0, windows.MEM_RELEASE)

	runtime.KeepAlive(data)

	return errors.Join(unlockErr, freeErr)
}
