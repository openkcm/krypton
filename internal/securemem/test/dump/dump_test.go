package main_test

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	scriptDest = "/usr/local/bin/analysis.sh"
	image      = "golang:1.26-alpine"
)

func TestProtection(t *testing.T) {
	// refer https://docs.github.com/en/actions/reference/workflows-and-actions/variables
	ci := os.Getenv("CI")
	if ci == "true" {
		t.Skip("skipping test: not running in CI environment")
	}

	t.Run("with memory protection=ON and dump protection=ON", func(t *testing.T) {
		ctx := t.Context()
		container := setupDocker(t, true)

		// Ensure container cleanup
		t.Cleanup(
			func() {
				if err := container.Terminate(ctx); err != nil {
					t.Logf("warning: failed to terminate container: %v", err)
				}
			})

		// Step 4: Retrieve and display container logs
		logs, err := container.Logs(ctx)
		require.NoError(t, err, "failed to get container logs")

		t.Cleanup(func() {
			if err := logs.Close(); err != nil {
				t.Logf("warning: failed to close logs: %v", err)
			}
		})

		isExposedSecretFound := false
		isPersistentVaultGetFound := false
		isCoreFileNotFound := false
		isPermissionDeniedFound := false
		isDumpAlertFound := false
		isDumpProtectionTestRan := false

		permissionDenied := regexp.MustCompile(`grep: /proc/\d+/maps: Permission denied`)
		coreFileNotFound := regexp.MustCompile(`strings: core.\d+: No such file or directory`)

		scanner := bufio.NewScanner(logs)
		for scanner.Scan() {
			text := scanner.Text()
			assert.NotContains(t, text, "PANIC RECOVERED")
			assert.NotContains(t, text, "ALERT UNEXPOSED SECRET FOUND: MYSECRETKEY123458901234567890123")

			if !isPermissionDeniedFound {
				regexMatch := permissionDenied.FindString(text)
				isPermissionDeniedFound = len(regexMatch) > 0
			}

			if !isCoreFileNotFound {
				regexMatch := coreFileNotFound.FindString(text)
				isCoreFileNotFound = len(regexMatch) > 0
			}
			if !isPersistentVaultGetFound {
				isPersistentVaultGetFound = strings.Contains(text, "SECRET FOUND IN MEMVAULT")
			}
			if !isExposedSecretFound {
				isExposedSecretFound = strings.Contains(text, "EXPOSED SECRET FOUND: EXPOSED_SECRET123456789012345678")
			}
			if !isDumpAlertFound {
				isDumpAlertFound = strings.Contains(text, "ALERT DUMP UNEXPOSED SECRET FOUND: MYSECRETKEY123458901234567890123")
			}
			if !isDumpProtectionTestRan {
				isDumpProtectionTestRan = strings.Contains(text, "RUNNING DUMP PROTECTION TEST")
			}
		}
		assert.True(t, isPermissionDeniedFound, "expected permission denied message not found in logs")
		assert.True(t, isCoreFileNotFound, "expected core file not found message not found in logs")
		assert.True(t, isPersistentVaultGetFound, "persistent vault secret not found in logs")
		assert.False(t, isExposedSecretFound, "exposed secret not found in logs")
		assert.False(t, isDumpAlertFound, "expected dump alert not found in logs")
		assert.True(t, isDumpProtectionTestRan, "dump protection test did not run as expected")

		// Step 5: Check exit code
		_, err = container.State(ctx)
		assert.NoError(t, err)
	})

	t.Run("with memory protection=ON and dump protection=OFF", func(t *testing.T) {
		ctx := t.Context()
		container := setupDocker(t, false)

		// Ensure container cleanup
		t.Cleanup(
			func() {
				if err := container.Terminate(ctx); err != nil {
					t.Logf("warning: failed to terminate container: %v", err)
				}
			})

		// Step 4: Retrieve and display container logs
		logs, err := container.Logs(ctx)
		require.NoError(t, err, "failed to get container logs")

		t.Cleanup(func() {
			if err := logs.Close(); err != nil {
				t.Logf("warning: failed to close logs: %v", err)
			}
		})

		isPersistentVaultGetFound := false
		isExposedSecretFound := false
		isCoreFileNotFound := false
		isPermissionDeniedFound := false
		isDumpProtectionTestRan := false

		permissionDenied := regexp.MustCompile(`grep: /proc/\d+/maps: Permission denied`)
		coreFileNotFound := regexp.MustCompile(`strings: core.\d+: No such file or directory`)

		scanner := bufio.NewScanner(logs)
		for scanner.Scan() {
			text := scanner.Text()
			assert.NotContains(t, text, "PANIC RECOVERED")
			assert.NotContains(t, text, "ALERT UNEXPOSED SECRET FOUND: MYSECRETKEY123458901234567890123")

			if !isPermissionDeniedFound {
				regexMatch := permissionDenied.FindString(text)
				isPermissionDeniedFound = len(regexMatch) > 0
			}

			if !isCoreFileNotFound {
				regexMatch := coreFileNotFound.FindString(text)
				isCoreFileNotFound = len(regexMatch) > 0
			}
			if !isPersistentVaultGetFound {
				isPersistentVaultGetFound = strings.Contains(text, "SECRET FOUND IN MEMVAULT")
			}
			if !isExposedSecretFound {
				isExposedSecretFound = strings.Contains(text, "EXPOSED SECRET FOUND: EXPOSED_SECRET123456789012345678")
			}
			if !isDumpProtectionTestRan {
				isDumpProtectionTestRan = strings.Contains(text, "RUNNING DUMP PROTECTION TEST")
			}
		}

		assert.False(t, isPermissionDeniedFound, "expected permission denied message not found in logs")
		assert.False(t, isCoreFileNotFound, "expected core file not found message not found in logs")
		assert.True(t, isPersistentVaultGetFound, "persistent vault secret not found in logs")
		assert.True(t, isExposedSecretFound, "exposed secret not found in logs")
		assert.False(t, isDumpProtectionTestRan, "dump protection test did not run as expected")

		// Step 5: Check exit code
		_, err = container.State(ctx)
		assert.NoError(t, err)
	})
}

func setupDocker(t *testing.T, isDumpProtectionEnabled bool) testcontainers.Container {
	t.Helper()

	testTimeout := 10 * time.Minute
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)

	t.Cleanup(cancel)

	root, err := os.Getwd()
	require.NoError(t, err)

	hostPath, err := filepath.Abs(filepath.Join(root, "../../../.."))
	require.NoError(t, err)

	req := testcontainers.ContainerRequest{
		Image: image,
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.Mounts = append(hc.Mounts, mount.Mount{
				Type:   mount.TypeBind,
				Source: hostPath,
				Target: "/app",
			})
		},
		Cmd: []string{
			"sh", "-c",
			fmt.Sprintf("chmod +x %s && %s", scriptDest, scriptDest),
		},

		// Copy the local binary into the container
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      "./analysis.sh",
				ContainerFilePath: scriptDest,
				FileMode:          0o755,
			},
		},

		WaitingFor: wait.ForLog("FINISHED").WithStartupTimeout(testTimeout),
		Env: map[string]string{
			"IS_DUMP_PROTECTION_ENABLED": strconv.FormatBool(isDumpProtectionEnabled),
			"TRIGGER_ID":                 strconv.Itoa(time.Now().Nanosecond()),
		},
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start container")

	return container
}
