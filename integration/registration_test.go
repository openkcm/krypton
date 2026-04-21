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

	db, dbConnStr := createDatabase(t)

	agentStore, err := sql.NewAgentStore(ctx, db)
	require.NoError(t, err, "failed to create agent store")

	// Build binaries for root server and agent
	rootBinary := buildBinary(t, "root", "../cmd/root")
	agentBinary := buildBinary(t, "agent", "../cmd/agent")

	// Use a dynamic port to avoid conflicts with other test runs
	port := freePort(t)

	// Start root server process
	rootCmd := exec.CommandContext(ctx, rootBinary)
	rootCmd.Stdout = os.Stdout
	rootCmd.Stderr = os.Stdout
	rootCmd.Env = append(os.Environ(),
		"DATABASE_URL="+dbConnStr,
		"SERVER_PORT="+port,
	)
	if coverDir != "" {
		rootCmd.Env = append(rootCmd.Env, "GOCOVERDIR="+coverDir)
	}

	err = rootCmd.Start()
	require.NoError(t, err, "failed to start root server process")
	t.Cleanup(func() {
		rootCmd.Process.Kill() //nolint:errcheck
		rootCmd.Wait()         //nolint:errcheck
	})

	// Wait for root server to accept connections
	waitForPort(t, port)

	t.Run("agent registration", func(t *testing.T) {
		// given
		agentID := uuid.NewString()

		agentCmd := exec.CommandContext(ctx, agentBinary)
		agentCmd.Stdout = os.Stdout
		agentCmd.Stderr = os.Stdout
		agentCmd.Env = append(os.Environ(),
			"AGENT_ID="+agentID,
			"ROOT_SERVER_PORT="+port,
		)
		if coverDir != "" {
			agentCmd.Env = append(agentCmd.Env, "GOCOVERDIR="+coverDir)
		}

		// when
		err = agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")

		t.Cleanup(func() {
			agentCmd.Process.Kill() //nolint:errcheck
			agentCmd.Wait()         //nolint:errcheck
		})

		require.Eventually(t, func() bool {
			result, err := agentStore.Get(ctx, store.GetAgentQuery{
				Name:       "agent-k1",
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
			require.Eventually(t, func() bool {
				result, err := agentStore.Get(ctx, store.GetAgentQuery{
					Name:       "agent-k1",
					InstanceID: agentID,
				})
				return err == nil && result.Registration.Status == core.AgentRegistrationStatusDeregistered
			}, 10*time.Second, 100*time.Millisecond, "expected agent to be deregistered in store after shutdown")

			t.Run("should delete agent registration after grace period", func(t *testing.T) {
				// when

				// simulate old heartbeat to trigger deletion after grace period
				_, err := agentStore.Register(ctx, store.RegisterAgentQuery{
					Registration: core.AgentRegistration{
						Name:          "agent-k1",
						InstanceID:    agentID,
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now() - clock.UnixNano(2*time.Minute),
					},
				})
				assert.NoError(t, err, "failed to update agent registration with old heartbeat")

				// then
				require.Eventually(t, func() bool {
					_, err := agentStore.Get(ctx, store.GetAgentQuery{
						Name:       "agent-k1",
						InstanceID: agentID,
					})
					return errors.Is(err, store.ErrAgentNotFound) // expect not found error
				}, 20*time.Second, 100*time.Millisecond, "expected agent registration to be deleted from store after grace period")
			})
		})
	})
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
