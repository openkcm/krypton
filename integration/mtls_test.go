package integration

import (
	"crypto/x509/pkix"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMTLS(t *testing.T) {
	// given
	ctx := t.Context()
	env := setupRootEnvWithMTLS(t)

	createTenantCmd := func() []string {
		return []string{"create", "tenant", "--name", uuid.NewString(), "--json", "--server", env.serverAddr}
	}

	t.Run("should fail given no login", func(t *testing.T) {
		// when
		cmd := newCLICommand(ctx, t.TempDir(), createTenantCmd()...)
		output, err := cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "failed to get token from store: token not found")
	})

	t.Run("should fail given noauth login against mtls server", func(t *testing.T) {
		// given
		homeDir := t.TempDir()

		// login with noauth
		cmd := newCLICommand(ctx, homeDir, "login", "no-auth")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "login setup failed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd()...)
		output, err = cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "code = Unavailable desc = connection error: desc = \"error reading server preface")
	})

	t.Run("should create tenant when noauth login is rejected by mtls server and re login with mtls", func(t *testing.T) {
		// given
		homeDir := t.TempDir()

		// login with noauth
		cmd := newCLICommand(ctx, homeDir, "login", "no-auth")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "login setup failed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// create tenant should fail with noauth
		cmd = newCLICommand(ctx, homeDir, createTenantCmd()...)
		output, err = cmd.CombinedOutput()
		require.Error(t, err, "command should fail, output: %s", string(output))
		require.Contains(t, string(output), "code = Unavailable desc = connection error: desc = \"error reading server preface")

		// re-login with mtls
		cCerts, ok := env.pki.clientCerts[env.allowedCN]
		require.True(t, ok, "client certs for allowedCN not found")

		cmd = newCLICommand(ctx, homeDir, "login", "mtls", "--cert", cCerts.certPEMPath, "--key", cCerts.keyPEMPath, "--ca", env.pki.caCertFilePath)
		output, err = cmd.CombinedOutput()
		require.NoError(t, err, "mtls login failed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd()...)
		output, err = cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
	})

	t.Run("should fail when client uses wrong CA to verify server certificate", func(t *testing.T) {
		// given
		homeDir := t.TempDir()

		// create a new PKI with same allowed CN but different CA (untrusted)
		untrustedPki := newTestPKI(t, env.allowedCN)
		untrustedCerts, ok := untrustedPki.clientCerts[env.allowedCN]
		require.True(t, ok, "client certs for allowedCN not found")

		// login with mtls using cert signed by untrusted CA
		cmd := newCLICommand(ctx, homeDir, "login", "mtls", "--cert", untrustedCerts.certPEMPath, "--key", untrustedCerts.keyPEMPath, "--ca", untrustedPki.caCertFilePath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "mtls login setup should succeed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd()...)
		output, err = cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "transport: authentication handshake failed: tls: failed to verify certificate")
	})

	t.Run("should reject client cert signed by untrusted CA even with allowed CN", func(t *testing.T) {
		// given
		homeDir := t.TempDir()

		// create a new PKI with same allowed CN but different CA (untrusted)
		untrustedPki := newTestPKI(t, env.allowedCN)
		untrustedCerts, ok := untrustedPki.clientCerts[env.allowedCN]
		require.True(t, ok, "client certs for allowedCN not found")

		// when
		// login with mtls using cert signed by untrusted CA
		cmd := newCLICommand(ctx, homeDir, "login", "mtls", "--cert", untrustedCerts.certPEMPath, "--key", untrustedCerts.keyPEMPath, "--ca", env.pki.caCertFilePath)

		// then
		output, err := cmd.CombinedOutput()
		assert.Error(t, err, "mtls login setup should fail, output: %s", string(output))
		assert.Contains(t, string(output), "Error: failed to verify cert/key pair:")
	})

	t.Run("should reject client cert with non-allowed CN signed by trusted CA", func(t *testing.T) {
		// given
		homeDir := t.TempDir()

		// issue a cert signed by the trusted CA but with a CN not in the allowlist
		nonAllowedCert, nonAllowedKey := issueCert(t, env.pki.caCert, env.pki.caPrivateKey, pkix.Name{CommonName: "non-allowed-cn"}, true, nil, false)
		nonAllowedCertPath := filepath.Join(homeDir, "non_allowed_cert.pem")
		nonAllowedKeyPath := filepath.Join(homeDir, "non_allowed_key.pem")

		writeFile(t, nonAllowedCertPath, nonAllowedCert)
		writeFile(t, nonAllowedKeyPath, nonAllowedKey)

		// login with mtls using cert that has a non-allowed CN
		cmd := newCLICommand(ctx, homeDir, "login", "mtls", "--cert", nonAllowedCertPath, "--key", nonAllowedKeyPath, "--ca", env.pki.caCertFilePath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "mtls login setup should succeed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd()...)
		output, err = cmd.CombinedOutput()

		// then
		assert.Error(t, err, "command should fail, output: %s", string(output))
		assert.Contains(t, string(output), "code = PermissionDenied desc = unauthorized client")
	})

	t.Run("should accept newly issued cert with allowed CN signed by trusted CA", func(t *testing.T) {
		// given
		homeDir := t.TempDir()

		// issue a new cert signed by the trusted CA with the allowed CN
		validCert, validKey := issueCert(t, env.pki.caCert, env.pki.caPrivateKey, pkix.Name{CommonName: env.allowedCN}, true, nil, false)
		validCertPath := filepath.Join(homeDir, "valid_cert.pem")
		validKeyPath := filepath.Join(homeDir, "valid_key.pem")

		writeFile(t, validCertPath, validCert)
		writeFile(t, validKeyPath, validKey)

		// login with mtls using the valid cert
		cmd := newCLICommand(ctx, homeDir, "login", "mtls", "--cert", validCertPath, "--key", validKeyPath, "--ca", env.pki.caCertFilePath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "mtls login should succeed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd()...)
		output, err = cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
	})

	t.Run("should create tenant given mtls login", func(t *testing.T) {
		// given
		homeDir := t.TempDir()

		// login with mtls
		cCerts, ok := env.pki.clientCerts[env.allowedCN]
		require.True(t, ok, "client certs for allowedCN not found")

		cmd := newCLICommand(ctx, homeDir, "login", "mtls", "--cert", cCerts.certPEMPath, "--key", cCerts.keyPEMPath, "--ca", env.pki.caCertFilePath)
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "mtls login failed, output: %s", string(output))
		require.Contains(t, string(output), "Login successful.")

		// when
		cmd = newCLICommand(ctx, homeDir, createTenantCmd()...)
		output, err = cmd.CombinedOutput()

		// then
		assert.NoError(t, err, "command should succeed, output: %s", string(output))
	})
}
