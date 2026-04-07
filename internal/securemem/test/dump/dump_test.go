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
		t.Skip("skipping test: running in CI environment")
	}

	tts := []struct {
		name                      string
		isDumpProtectionEnabled   bool
		isExposedSecretFound      bool
		isPersistentVaultGetFound bool
		isCoreFileNotFound        bool
		isPermissionDeniedFound   bool
		isDumpProtectionTestRan   bool
	}{
		{
			name:                      "with memory protection=ON and dump protection=ON",
			isDumpProtectionEnabled:   true,
			isPermissionDeniedFound:   true,
			isCoreFileNotFound:        true,
			isPersistentVaultGetFound: true,
			isDumpProtectionTestRan:   true,
			isExposedSecretFound:      false,
		},
		{
			name:                      "with memory protection=ON and dump protection=OFF",
			isDumpProtectionEnabled:   false,
			isPermissionDeniedFound:   false,
			isCoreFileNotFound:        false,
			isDumpProtectionTestRan:   false,
			isPersistentVaultGetFound: true,
			isExposedSecretFound:      true,
		},
	}

	permissionDenied := regexp.MustCompile(`grep: /proc/\d+/maps: Permission denied`)
	coreFileNotFound := regexp.MustCompile(`strings: core.\d+: No such file or directory`)

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			ctr := setupDocker(t, tt.isDumpProtectionEnabled)

			t.Cleanup(func() {
				if err := ctr.Terminate(ctx); err != nil {
					t.Logf("warning: failed to terminate container: %v", err)
				}
			})

			logs, err := ctr.Logs(ctx)
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
			isDumpProtectionTestRan := false

			scanner := bufio.NewScanner(logs)
			for scanner.Scan() {
				text := scanner.Text()
				assert.NotContains(t, text, "PANIC RECOVERED")
				assert.NotContains(t, text, "ALERT SECUREMEM SECRET FOUND:")

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
					isExposedSecretFound = strings.Contains(text, "UNSECURED SECRET FOUND:")
				}
				if !isDumpProtectionTestRan {
					isDumpProtectionTestRan = strings.Contains(text, "RUNNING DUMP PROTECTION TEST")
				}
			}
			require.NoError(t, scanner.Err(), "error reading container logs")

			assert.Equal(t, tt.isPersistentVaultGetFound, isPersistentVaultGetFound, "persistent vault secret presence does not match in logs")
			assert.Equal(t, tt.isPermissionDeniedFound, isPermissionDeniedFound, "expected permission denied message presence does not match in logs")
			assert.Equal(t, tt.isCoreFileNotFound, isCoreFileNotFound, "expected core file not found message presence does not match in logs")
			assert.Equal(t, tt.isExposedSecretFound, isExposedSecretFound, "exposed secret presence does not match in logs")
			assert.Equal(t, tt.isDumpProtectionTestRan, isDumpProtectionTestRan, "dump protection test ran presence does not match as expected")

			state, err := ctr.State(ctx)
			require.NoError(t, err, "failed to get container state")
			assert.Equal(t, 0, state.ExitCode, "container exited with non-zero code")
		})
	}
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
			"TRIGGER_ID":                 strconv.FormatInt(time.Now().UnixNano(), 10),
		},
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start container")

	return ctr
}
