package main_test

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDestroyCleanup verifies that explicit Destroy() prevents the GC cleanup
// from firing (cleanup.Stop() deregisters it). Runs in a subprocess because
// SIGSEGV from double-destroy cannot be caught by recover().
func TestDestroyCleanup(t *testing.T) {
	// given
	cmd := exec.CommandContext(t.Context(), "go", "run", "main.go", "destroy-cleanup")

	// when
	out, err := cmd.CombinedOutput()

	// then
	assert.NoError(t, err)
	outStr := string(out)

	assert.Contains(t, outStr, "start destroy-cleanup")
	// GC cleanup must NOT fire — Destroy() already called cleanup.Stop()
	assert.NotContains(t, outStr, "securemem: cleanup started")
	assert.NotContains(t, outStr, "securemem: failed to destroy secure memory region")
	assert.NotContains(t, outStr, "securemem: cleanup finished")
	// Explicit Destroy() ran successfully
	assert.Contains(t, outStr, "securemem: destroy started")
	assert.Contains(t, outStr, "securemem: destroy finished")
	assert.Contains(t, outStr, "finish destroy-cleanup")
	assert.NotContains(t, outStr, "PANIC RECOVERED")
}

// TestCleanupOnly verifies that without explicit Destroy(), the GC cleanup
// fires and securely destroys the memory. Runs in a subprocess because
// runtime.AddCleanup requires the object to be truly unreachable.
func TestCleanupOnly(t *testing.T) {
	// given
	cmd := exec.CommandContext(t.Context(), "go", "run", "main.go", "cleanup-only")

	// when
	out, err := cmd.CombinedOutput()

	// then
	assert.NoError(t, err)
	outStr := string(out)

	assert.Contains(t, outStr, "start cleanup-only")
	// GC cleanup MUST fire — no explicit Destroy() was called
	assert.Contains(t, outStr, "securemem: cleanup started")
	assert.NotContains(t, outStr, "securemem: failed to destroy secure memory region")
	assert.Contains(t, outStr, "securemem: destroy started")
	assert.Contains(t, outStr, "securemem: destroy finished")
	assert.Contains(t, outStr, "securemem: cleanup finished")
	assert.Contains(t, outStr, "finish cleanup-only")
	assert.NotContains(t, outStr, "PANIC RECOVERED")
}
