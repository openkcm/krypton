// Test helper binary for cleanup_test.go. Runs as a subprocess because
// runtime.AddCleanup requires true unreachability, and accessing munmapped
// memory causes fatal SIGSEGV that recover() cannot catch.
package main

import (
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/openkcm/krypton/internal/securemem"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})))
	defer func() {
		if r := recover(); r != nil {
			slog.Error("PANIC RECOVERED:", "recover", r)
		}
	}()

	tc := os.Args[1]

	switch tc {
	case "cleanup-only":
		cleanupOnly()
	case "destroy-cleanup":
		destroyCleanupOnly()
	}
}

// destroyCleanupOnly verifies that explicit Destroy() prevents the GC cleanup
// from firing. Destroy() calls cleanup.Stop(), so no cleanup logs should appear.
func destroyCleanupOnly() {
	slog.Info("start destroy-cleanup")

	// Allocate in a separate function so the *Data is guaranteed off the stack
	// when it returns — making it truly unreachable for GC.
	allocateAndDestroy()

	awaitGC()

	slog.Info("finish destroy-cleanup")
}

// cleanupOnly verifies that without explicit Destroy(), the GC cleanup fires
// and securely destroys the memory via dataCleanupRef.Destroy().
func cleanupOnly() {
	slog.Info("start cleanup-only")

	// Allocate in a separate function so the *Data is guaranteed off the stack
	// when it returns — making it truly unreachable for GC.
	allocateData()

	awaitGC()

	slog.Info("finish cleanup-only")
}

// allocateAndDestroy creates a *Data, calls Destroy() twice (proving idempotency),
// and drops the reference. Once this returns, the *Data is off the stack and eligible
// for GC — but cleanup.Stop() was already called, so no cleanup callback should fire.
func allocateAndDestroy() {
	subj, err := securemem.NewData("destroy-cleanup", 3)
	if err != nil {
		panic(err)
	}

	// First Destroy: zeroes + munmaps, sets data=nil, calls cleanup.Stop()
	err = subj.Destroy()
	if err != nil {
		panic(err)
	}

	// Second Destroy: idempotent (data is nil)
	err = subj.Destroy()
	if err != nil {
		panic(err)
	}
}

// allocateData creates a *Data without holding a reference in the caller's frame.
// Once this function returns, the *Data is unreachable and eligible for GC collection.
func allocateData() {
	_, err := securemem.NewData("cleanup-only", 3)
	if err != nil {
		panic(err)
	}
}

// awaitGC forces garbage collection and waits for async cleanup callbacks to execute.
// runtime.GC() is synchronous (completes the collection), but cleanup callbacks run
// on a background goroutine — the sleep gives that goroutine time to execute.
func awaitGC() {
	runtime.GC()
	time.Sleep(1 * time.Second)
}
