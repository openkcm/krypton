package integration

import (
	"crypto/x509/pkix"
	"errors"
	"os"
	"path/filepath"
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

const allowedAgentName = "agent-k1"

func TestRegistration(t *testing.T) {
	// given
	ctx := t.Context()

	// pki
	pki := newTestPKI(t, allowedAgentName)
	clientPki, ok := pki.clientCerts[allowedAgentName]
	require.True(t, ok, "client certificate for agent not found in PKI")

	// Setup test database and store
	db, dbConnStr := createDatabase(t)

	// Create agent store
	rootAgentStore := sql.NewAgentStore(db)

	// Build binaries for root server and agent
	rootBinary := buildBinary(t, "root", "../cmd/root")
	agentBinary := buildBinary(t, "agent", "../cmd/agent")

	// Use a dynamic rootPort to avoid conflicts with other test runs
	rootPort := freePort(t)
	rootCfgPath := writeRootAgentConfigWithMTLS(t, allowedAgentName, pki.serverCertPath, pki.serverKeyPath, pki.caCertFilePath)

	// Start root server process
	rootCmd := createCmd(t, rootBinary, []string{
		"ROOT_CONFIG_PATH=" + rootCfgPath,
		"DATABASE_URL=" + dbConnStr,
		"SERVER_PORT=" + rootPort,
		"KRYPTON_ROOT_KEY=" + testKeyBase64,
	})
	err := rootCmd.Start()
	require.NoError(t, err, "failed to start root server process")

	// Wait for root server to accept connections
	waitForPort(t, rootPort)

	t.Run("should register agent", func(t *testing.T) {
		// given
		agentID := uuid.NewString()
		agentPort := freePort(t)
		_, agentDBConnStr := createDatabase(t)

		agentCfgPath := writeAgentConfigWithMTLS(t, allowedAgentName, localAddress(rootPort), clientPki.certPEMPath, clientPki.keyPEMPath, pki.caCertFilePath)

		agentCmd := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort,
		})

		// when
		// start agent process which should trigger registration with root server
		err := agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")

		// wait for agent to be fully ready (operator RPC server listening)
		waitForPort(t, agentPort)

		// then
		// wait for agent registration to appear in store with registered status
		require.Eventually(t, func() bool {
			result, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
				Name:       allowedAgentName,
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
				result, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
					Name:       allowedAgentName,
					InstanceID: agentID,
				})
				return err == nil && result.Registration.Status == core.AgentRegistrationStatusDeregistered
			}, 10*time.Second, 100*time.Millisecond, "expected agent to be deregistered in store after shutdown")

			t.Run("should delete agent registration after grace period", func(t *testing.T) {
				// when
				// simulate old heartbeat to trigger deletion after grace period
				_, err := rootAgentStore.Register(ctx, store.RegisterAgentQuery{
					Registration: core.AgentRegistration{
						Name:          allowedAgentName,
						InstanceID:    agentID,
						Status:        core.AgentRegistrationStatusDeregistered,
						LastHeartbeat: clock.Now() - clock.UnixNano(2*time.Minute),
					},
				})
				assert.NoError(t, err, "failed to update agent registration with old heartbeat")

				// then
				// wait for agent registration to be deleted from store after grace period
				require.Eventually(t, func() bool {
					_, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
						Name:       allowedAgentName,
						InstanceID: agentID,
					})
					return errors.Is(err, store.ErrAgentNotFound) // expect not found error
				}, 20*time.Second, 100*time.Millisecond, "expected agent registration to be deleted from store after grace period")
			})
		})
	})

	t.Run("should reject agent with wrong mtls certificates", func(t *testing.T) {
		// given
		agentID := uuid.NewString()
		agentPort := freePort(t)
		_, agentDBConnStr := createDatabase(t)

		// create a new PKI with invalid certificates for the agent
		invalidPki := newTestPKI(t, allowedAgentName)
		invalidClientPki, ok := invalidPki.clientCerts[allowedAgentName]
		require.True(t, ok, "client certificate for agent not found in invalid PKI")

		agentCfgPath := writeAgentConfigWithMTLS(t, allowedAgentName, localAddress(rootPort), invalidClientPki.certPEMPath, invalidClientPki.keyPEMPath, invalidPki.caCertFilePath)

		agentCmd := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort,
		})

		// when
		// start agent process which should fail to register due to TLS mismatch
		err := agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")

		// then
		// the agent should exit with a non-zero code because the TLS handshake
		// fails (server cert signed by unknown authority from agent's perspective)
		waitCh := make(chan error, 1)
		go func() {
			waitCh <- agentCmd.Wait()
		}()

		select {
		case <-time.After(10 * time.Second):
			agentCmd.Process.Kill() //nolint:errcheck
			<-waitCh                // drain goroutine so cleanup's Wait() doesn't race
			require.Fail(t, "agent process did not exit within timeout when using wrong mTLS certificates")
		case waitErr := <-waitCh:
			require.Error(t, waitErr, "agent should exit with error when using wrong mTLS certificates")
		}

		// verify no registration appeared in the store
		_, err = rootAgentStore.Get(ctx, store.GetAgentQuery{
			Name:       allowedAgentName,
			InstanceID: agentID,
		})
		require.ErrorIs(t, err, store.ErrAgentNotFound, "agent should not have registered with invalid certificates")
	})

	t.Run("should not start agent without root server", func(t *testing.T) {
		// given
		agentID := uuid.NewString()
		agentPort := freePort(t)
		_, agentDBConnStr := createDatabase(t)
		nonExistingRootPort := freePort(t) // Use a port that is not being listened on

		agentCfgPath := writeAgentConfigWithMTLS(t, allowedAgentName, localAddress(nonExistingRootPort), clientPki.certPEMPath, clientPki.keyPEMPath, pki.caCertFilePath)

		agentCmd := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort,
		})

		// when
		err := agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- agentCmd.Wait()
		}()

		select {
		case <-time.After(10 * time.Second):
			agentCmd.Process.Kill() //nolint:errcheck
			<-waitCh                // drain goroutine so cleanup's Wait() doesn't race
			require.Fail(t, "agent process did not exit within timeout when root server is down")
		case waitErr := <-waitCh:
			require.Error(t, waitErr, "agent should exit with error when root server is down")
		}
	})

	t.Run("should not start agent if name is not in root config", func(t *testing.T) {
		// given
		agentID := uuid.NewString()
		agentPort := freePort(t)
		_, agentDBConnStr := createDatabase(t)

		agentCfgPath := writeAgentConfigWithMTLS(t, "invalid-agent-name", localAddress(rootPort), clientPki.certPEMPath, clientPki.keyPEMPath, pki.caCertFilePath)

		agentCmd := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort,
		})

		// when
		err := agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")

		waitCh := make(chan error, 1)
		go func() {
			waitCh <- agentCmd.Wait()
		}()

		select {
		case <-time.After(10 * time.Second):
			agentCmd.Process.Kill() //nolint:errcheck
			<-waitCh                // drain goroutine so cleanup's Wait() doesn't race
			require.Fail(t, "agent process did not exit within timeout when agent name is not in root config")
		case waitErr := <-waitCh:
			require.Error(t, waitErr, "agent should exit with error when agent name is not in root config")
		}
	})

	t.Run("should register agent with newly issued certificates", func(t *testing.T) {
		// given
		homeDir := t.TempDir()
		agentID := uuid.NewString()
		agentPort := freePort(t)
		_, agentDBConnStr := createDatabase(t)

		// issue a new cert signed by the trusted CA with the allowed CN
		uris := makeURIs(t, allowedAgentName)
		validCert, validKey := issueCert(t, pki.caCert, pki.caPrivateKey, pkix.Name{CommonName: allowedAgentName}, true, nil, uris, false)
		validCertPath := filepath.Join(homeDir, "valid_cert.pem")
		validKeyPath := filepath.Join(homeDir, "valid_key.pem")

		writeFile(t, validCertPath, validCert)
		writeFile(t, validKeyPath, validKey)

		agentCfgPath := writeAgentConfigWithMTLS(t, allowedAgentName, localAddress(rootPort), validCertPath, validKeyPath, pki.caCertFilePath)

		agentCmd := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort,
		})

		// when
		// start agent process which should trigger registration with root server
		err := agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")

		// wait for agent to be fully ready (operator RPC server listening)
		waitForPort(t, agentPort)

		// then
		// wait for agent registration to appear in store with registered status
		require.Eventually(t, func() bool {
			result, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
				Name:       allowedAgentName,
				InstanceID: agentID,
			})
			return err == nil && result.Registration.Status == core.AgentRegistrationStatusRegistered
		}, 10*time.Second, 100*time.Millisecond, "expected exactly one agent registration in store")
	})

	t.Run("should register multiple agent instances", func(t *testing.T) {
		// given
		agentID1 := uuid.NewString()
		agentID2 := uuid.NewString()
		agentPort1 := freePort(t)
		agentPort2 := freePort(t)
		_, agentDBConnStr := createDatabase(t)

		agentCfgPath1 := writeAgentConfigWithMTLS(t, allowedAgentName, localAddress(rootPort), clientPki.certPEMPath, clientPki.keyPEMPath, pki.caCertFilePath)
		agentCfgPath2 := writeAgentConfigWithMTLS(t, allowedAgentName, localAddress(rootPort), clientPki.certPEMPath, clientPki.keyPEMPath, pki.caCertFilePath)

		agentCmd1 := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID1,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath1,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort1,
		})

		agentCmd2 := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID2,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath2,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort2,
		})

		// when
		err := agentCmd1.Start()
		require.NoError(t, err, "failed to start first agent process")

		err = agentCmd2.Start()
		require.NoError(t, err, "failed to start second agent process")

		waitForPort(t, agentPort1)
		waitForPort(t, agentPort2)

		// then
		// wait for both agent registrations to appear in store with registered status
		require.Eventually(t, func() bool {
			result1, err1 := rootAgentStore.Get(ctx, store.GetAgentQuery{
				Name:       allowedAgentName,
				InstanceID: agentID1,
			})
			result2, err2 := rootAgentStore.Get(ctx, store.GetAgentQuery{
				Name:       allowedAgentName,
				InstanceID: agentID2,
			})
			return err1 == nil && result1.Registration.Status == core.AgentRegistrationStatusRegistered &&
				err2 == nil && result2.Registration.Status == core.AgentRegistrationStatusRegistered
		}, 10*time.Second, 100*time.Millisecond, "expected both agent registrations to be in store")
	})

	t.Run("should reject agent with expired client certificate", func(t *testing.T) {
		// given
		agentID := uuid.NewString()
		agentPort := freePort(t)
		_, agentDBConnStr := createDatabase(t)
		homeDir := t.TempDir()

		// issue an expired client certificate signed by the trusted CA
		uris := makeURIs(t, allowedAgentName)
		expiredCert, expiredKey := issueCert(t, pki.caCert, pki.caPrivateKey, pkix.Name{CommonName: allowedAgentName}, true, nil, uris, true)
		expiredCertPath := filepath.Join(homeDir, "expired_cert.pem")
		expiredKeyPath := filepath.Join(homeDir, "expired_key.pem")

		writeFile(t, expiredCertPath, expiredCert)
		writeFile(t, expiredKeyPath, expiredKey)

		agentCfgPath := writeAgentConfigWithMTLS(t, allowedAgentName, localAddress(rootPort), expiredCertPath, expiredKeyPath, pki.caCertFilePath)

		agentCmd := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort,
		})

		// when
		err := agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")

		// then
		// the agent should exit with a non-zero code because the TLS handshake
		// fails (expired client certificate rejected by server)
		waitCh := make(chan error, 1)
		go func() {
			waitCh <- agentCmd.Wait()
		}()

		select {
		case <-time.After(10 * time.Second):
			agentCmd.Process.Kill() //nolint:errcheck
			<-waitCh                // drain goroutine so cleanup's Wait() doesn't race
			require.Fail(t, "agent process did not exit within timeout when using expired certificate")
		case waitErr := <-waitCh:
			require.Error(t, waitErr, "agent should exit with error when using expired certificate")
		}

		// verify no registration appeared in the store
		_, err = rootAgentStore.Get(ctx, store.GetAgentQuery{
			Name:       allowedAgentName,
			InstanceID: agentID,
		})
		require.ErrorIs(t, err, store.ErrAgentNotFound, "agent should not have registered with expired certificate")
	})

	t.Run("should transition through unhealthy/deregistered/deleted on SIGKILL", func(t *testing.T) {
		// given
		agentID := uuid.NewString()
		agentPort := freePort(t)
		_, agentDBConnStr := createDatabase(t)

		agentCfgPath := writeAgentConfigWithMTLS(t, allowedAgentName, localAddress(rootPort), clientPki.certPEMPath, clientPki.keyPEMPath, pki.caCertFilePath)
		agentCmd := createCmd(t, agentBinary, []string{
			"AGENT_ID=" + agentID,
			"AGENT_BOOTSTRAP_CONFIG_PATH=" + agentCfgPath,
			"AGENT_DATABASE_URL=" + agentDBConnStr,
			"AGENT_PORT=" + agentPort,
		})

		err := agentCmd.Start()
		require.NoError(t, err, "failed to start agent process")
		waitForPort(t, agentPort)

		require.Eventually(t, func() bool {
			result, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
				Name:       allowedAgentName,
				InstanceID: agentID,
			})
			return err == nil && result.Registration.Status == core.AgentRegistrationStatusRegistered
		}, 10*time.Second, 100*time.Millisecond, "expected agent to be registered")

		// when
		// kill the agent process without graceful shutdown (bypasses deregister RPC)
		err = agentCmd.Process.Kill()
		require.NoError(t, err, "failed to SIGKILL agent")

		// then
		// verify agent is still registered since no deregister RPC was sent
		result, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
			Name:       allowedAgentName,
			InstanceID: agentID,
		})
		require.NoError(t, err)
		require.NotEqual(t, core.AgentRegistrationStatusDeregistered, result.Registration.Status,
			"agent should not be deregistered after SIGKILL (no graceful shutdown)")

		// simulate stale heartbeat (>30s) to trigger unhealthy transition by the worker
		_, err = rootAgentStore.Register(ctx, store.RegisterAgentQuery{
			Registration: core.AgentRegistration{
				Name:          allowedAgentName,
				InstanceID:    agentID,
				Status:        result.Registration.Status,
				LastHeartbeat: clock.Now() - clock.UnixNano(45*time.Second),
			},
		})
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			r, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
				Name:       allowedAgentName,
				InstanceID: agentID,
			})
			return err == nil && r.Registration.Status == core.AgentRegistrationStatusUnhealthy
		}, 20*time.Second, 100*time.Millisecond, "expected agent to become unhealthy")

		// simulate stale heartbeat (>90s) to trigger deregister transition by the worker
		_, err = rootAgentStore.Register(ctx, store.RegisterAgentQuery{
			Registration: core.AgentRegistration{
				Name:          allowedAgentName,
				InstanceID:    agentID,
				Status:        core.AgentRegistrationStatusUnhealthy,
				LastHeartbeat: clock.Now() - clock.UnixNano(95*time.Second),
			},
		})
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			r, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
				Name:       allowedAgentName,
				InstanceID: agentID,
			})
			return errors.Is(err, store.ErrAgentNotFound) ||
				(err == nil && r.Registration.Status == core.AgentRegistrationStatusDeregistered)
		}, 20*time.Second, 100*time.Millisecond, "expected agent to become deregistered or deleted")

		// re-insert as de-registered with stale heartbeat (>120s) to verify deletion by the worker
		_, err = rootAgentStore.Register(ctx, store.RegisterAgentQuery{
			Registration: core.AgentRegistration{
				Name:          allowedAgentName,
				InstanceID:    agentID,
				Status:        core.AgentRegistrationStatusDeregistered,
				LastHeartbeat: clock.Now() - clock.UnixNano(3*time.Minute),
			},
		})
		require.NoError(t, err)

		require.Eventually(t, func() bool {
			_, err := rootAgentStore.Get(ctx, store.GetAgentQuery{
				Name:       allowedAgentName,
				InstanceID: agentID,
			})
			return errors.Is(err, store.ErrAgentNotFound)
		}, 20*time.Second, 100*time.Millisecond, "expected agent record to be deleted from store")
	})
}
