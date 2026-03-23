package main_test

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"

	main "github.com/openkcm/krypton/internal/securemem/test/readonlyrun"
)

// This test verifies that attempting to write to a read-only memory region results
// in a process termination (panic). It runs the main.go program, which creates a
// secure memory region, marks it as read-only, and then tries to modify it.
// The test checks that an error occurs and that the output contains the expected
// secret value and error message, confirming that the read-only protection is
// working as intended.
func TestRun(t *testing.T) {
	// given

	// when
	cmd := exec.CommandContext(t.Context(), "go", "run", "main.go")
	output, err := cmd.CombinedOutput()

	// then

	assert.Error(t, err, "Expected an error when writing to read-only memory")

	outputStr := string(output)

	// It should not contain the "PANIC RECOVERED:" message, as the process should
	// have been terminated due to the read-only protection.
	assert.NotContains(t, outputStr, "PANIC RECOVERED:")

	// The output should contain the secret value followed by an error message about the unexpected fault address
	assert.Contains(t, outputStr, main.SecretData+"\nunexpected fault address")
}
