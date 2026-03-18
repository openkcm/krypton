package main_test

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRun(t *testing.T) {
	// given
	secret := "MYSECRET1234567890"

	// when
	cmd := exec.CommandContext(t.Context(), "go", "run", "main.go")
	output, err := cmd.CombinedOutput()

	// then
	assert.Error(t, err, "Expected an error when writing to read-only memory")
	outputStr := string(output)
	assert.NotContains(t, outputStr, "PANIC RECOVERED:")
	assert.Contains(t, outputStr, secret+"\nunexpected fault address")
}
