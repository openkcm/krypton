package integration

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/clock"
	"github.com/openkcm/krypton/internal/core"
	"github.com/openkcm/krypton/pkg/store"
	"github.com/openkcm/krypton/pkg/store/sql"
)

func TestRegistration(t *testing.T) {
	// given
	ctx := t.Context()
	agentName := "agent-k1"
	agentID := uuid.NewString()

	// Setup test database and store
	db, dbConnStr := createDatabase(t)

	// Create agent store
	agentStore := sql.NewAgentStore(db)

	// Build binaries for root server and agent
	rootBinary := buildBinary(t, "root", "../cmd/root")
	agentBinary := buildBinary(t, "agent", "../cmd/agent")

	// Use a dynamic rootPort to avoid conflicts with other test runs
	rootPort := freePort(t)
	agentPort := freePort(t)
	rootCfgPath := writeRootConfig(t, agentName, agentPort)

	// Start root server process
	rootCmd := createCmd(t, rootBinary, []string{
		"ROOT_CONFIG_PATH=" + rootCfgPath,
		"DATABASE_URL=" + dbConnStr,
		"SERVER_PORT=" + rootPort,
	})
	err := rootCmd.Start()
	require.NoError(t, err, "failed to start root server process")

	// Wait for root server to accept connections
	waitForPort(t, rootPort)

	t.Run("agent registration", func(t *testing.T) {
		// given
		_, agentDBConnStr := createDatabase(t)
		agentCfgPath := writeAgentConfig(t, agentName, "localhost:"+rootPort)
		agentCmd := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
			"ROOT_SERVER_PORT=" + rootPort,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort,
		})

		// when
		// start agent process which should trigger registration with root server
		err = agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")

		// then
		// wait for agent registration to appear in store with registered status
		require.Eventually(t, func() bool {
			result, err := agentStore.Get(ctx, store.GetAgentQuery{
				Name:       agentName,
				InstanceID: agentID,
			})
			return err == nil && result.Registration.Status == core.AgentRegistrationStatusRegistered
		}, 10*time.Second, 100*time.Millisecond, "expected exactly one agent registration in store")

		t.Run("should deregister agent on shutdown", func(t *testing.T) {
			// when
			// send interrupt signal to agent process to trigger graceful shutdown
			err := agentCmd.Process.Signal(os.Interrupt)
			require.NoError(t, err, "failed to send interrupt signal to agent process")

			// then
			// wait for agent registration to be updated to deregistered status in store
			require.Eventually(t, func() bool {
				result, err := agentStore.Get(ctx, store.GetAgentQuery{
					Name:       agentName,
					InstanceID: agentID,
				})
				return err == nil && result.Registration.Status == core.AgentRegistrationStatusDeregistered
			}, 10*time.Second, 100*time.Millisecond, "expected agent to be deregistered in store after shutdown")

			t.Run("should delete agent registration after grace period", func(t *testing.T) {
				// when
				// simulate old heartbeat to trigger deletion after grace period
				_, err := agentStore.Register(ctx, store.RegisterAgentQuery{
					Registration: core.AgentRegistration{
						Name:          agentName,
						InstanceID:    agentID,
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now() - clock.UnixNano(2*time.Minute),
					},
				})
				assert.NoError(t, err, "failed to update agent registration with old heartbeat")

				// then
				// wait for agent registration to be deleted from store after grace period
				require.Eventually(t, func() bool {
					_, err := agentStore.Get(ctx, store.GetAgentQuery{
						Name:       agentName,
						InstanceID: agentID,
					})
					return errors.Is(err, store.ErrAgentNotFound) // expect not found error
				}, 20*time.Second, 100*time.Millisecond, "expected agent registration to be deleted from store after grace period")
			})
		})
	})
}

func createCmd(t *testing.T, path string, env []string) *exec.Cmd {
	t.Helper()
	ctx := t.Context()
	cmd := exec.CommandContext(ctx, path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stdout
	cmd.Env = append(os.Environ(),
		env...,
	)
	if coverDir != "" {
		cmd.Env = append(cmd.Env, "GOCOVERDIR="+coverDir)
	}

	t.Cleanup(func() {
		cmd.Process.Kill() //nolint:errcheck
		cmd.Wait()         //nolint:errcheck
	})

	return cmd
}

func waitForPort(t *testing.T, port string) {
	t.Helper()

	ctx := t.Context()

	dialer := net.Dialer{Timeout: time.Second}
	require.Eventually(t, func() bool {
		conn, err := dialer.DialContext(ctx, "tcp", "localhost:"+port)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 10*time.Second, 100*time.Millisecond, "server did not become ready on port "+port)
}

func buildBinary(t *testing.T, binaryName string, sourceDir string) string {
	t.Helper()

	ctx := t.Context()

	binaryPath := filepath.Join(t.TempDir(), binaryName)

	buildArgs := []string{"build", "-o", binaryPath}
	if coverDir != "" {
		buildArgs = append(buildArgs, "-cover", "-covermode=atomic")
	}
	buildArgs = append(buildArgs, sourceDir)

	buildCmd := exec.CommandContext(ctx, "go", buildArgs...)
	buildCmd.Stderr = os.Stderr

	err := buildCmd.Run()
	require.NoError(t, err, "failed to build agent binary")

	return binaryPath
}

func freePort(t *testing.T) string {
	t.Helper()

	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "localhost:0")
	require.NoError(t, err, "failed to find a free port")

	defer l.Close()

	addr, ok := l.Addr().(*net.TCPAddr)
	require.True(t, ok, "unexpected address type: %T", l.Addr())

	return strconv.Itoa(addr.Port)
}
