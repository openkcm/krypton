package integration

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMTLS(t *testing.T) {
	ctx := t.Context()
	env := setupRootEnvWithMTLS(t)

	t.Run("should fail given no login", func(t *testing.T) {
		// given
		createTenantCmd := []string{"create", "tenant", "--name", uuid.NewString(), "--json", "--server", env.serverAddr}

		// when
		cmd := newCLICommand(ctx, t.TempDir(), createTenantCmd...)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "failed to get token from store: token not found")
	})

	t.Run("should fail given noauth login against mtls server", func(t *testing.T) {
		// given
		homeDir := t.TempDir()
		createTenantCmd := []string{"create", "tenant", "--name", uuid.NewString(), "--json", "--server", env.serverAddr}

		// login with noauth
		cmd := newCLICommand(ctx, homeDir, "login", "no-auth")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "login setup failed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd...)
		output, err = cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "code = Unavailable desc = connection error: desc = \"error reading server preface")
	})

	t.Run("should create tenant when noauth login is rejected by mtls server and re login with mtls", func(t *testing.T) {
		// given
		homeDir := t.TempDir()
		createTenantCmd := []string{"create", "tenant", "--name", uuid.NewString(), "--json", "--server", env.serverAddr}

		// login with noauth
		cmd := newCLICommand(ctx, homeDir, "login", "no-auth")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "login setup failed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// create tenant should fail with noauth
		cmd = newCLICommand(ctx, homeDir, createTenantCmd...)
		output, err = cmd.CombinedOutput()
		require.Error(t, err, "command should fail, output: %s", string(output))
		require.Contains(t, string(output), "code = Unavailable desc = connection error: desc = \"error reading server preface")

		// re-login with mtls
		cmd = newCLICommand(ctx, homeDir, "login", "mtls", "--cert", env.clientCertPath, "--key", env.clientKeyPath, "--ca", env.caPath)
		output, err = cmd.CombinedOutput()
		require.NoError(t, err, "mtls login failed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd...)
		output, err = cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
	})

	t.Run("should create tenant given mtls login", func(t *testing.T) {
		// given
		homeDir := t.TempDir()
		createTenantCmd := []string{"create", "tenant", "--name", uuid.NewString(), "--json", "--server", env.serverAddr}

		// login with mtls
		cmd := newCLICommand(ctx, homeDir, "login", "mtls", "--cert", env.clientCertPath, "--key", env.clientKeyPath, "--ca", env.caPath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "mtls login failed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd...)
		output, err = cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
	})
}
