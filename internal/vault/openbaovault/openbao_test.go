package openbaovault_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	openbao "github.com/openbao/openbao/api/v2"

	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/openbaovault"
)

const validToken = "token123"

type tlsCerts struct {
	caCertPEM  []byte
	srvCertPEM []byte
	srvKeyPEM  []byte
	cliCertPEM []byte
	cliKeyPEM  []byte
}

func TestLogin(t *testing.T) {
	// given
	ctx := t.Context()

	// generate certificates
	certs := generateCerts(t)

	// start a container
	port := startOpenBaoWithMTLS(t, certs)

	t.Run("should successfully prepare tenant", func(t *testing.T) {
		// given
		cli, err := openbaovault.New(
			"test-client",
			func(c *openbao.Client) error {
				c.SetToken(validToken)
				err := c.SetAddress("https://localhost:" + port)
				if err != nil {
					return err
				}
				return c.ConfigureTLS(&openbao.TLSConfig{
					CACertBytes:     certs.caCertPEM,
					ClientCertBytes: certs.cliCertPEM,
					ClientKeyBytes:  certs.cliKeyPEM,
				})
			},
		)
		require.NoError(t, err)

		// when
		resp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: uuid.NewString(), Name: "Test Tenant"})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should fail to prepare tenant with invalid token", func(t *testing.T) {
		// given
		cli, err := openbaovault.New(
			"test-client",
			func(c *openbao.Client) error {
				c.SetToken("invalid-token")
				err := c.SetAddress("https://localhost:" + port)
				if err != nil {
					return err
				}
				return c.ConfigureTLS(&openbao.TLSConfig{
					CACertBytes:     certs.caCertPEM,
					ClientCertBytes: certs.cliCertPEM,
					ClientKeyBytes:  certs.cliKeyPEM,
				})
			},
		)
		require.NoError(t, err)

		// when
		resp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: uuid.NewString(), Name: "Test Tenant"})

		// then
		require.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail to prepare tenant with invalid certs", func(t *testing.T) {
		// given
		anotherCerts := generateCerts(t)
		cli, err := openbaovault.New(
			"test-client",
			func(c *openbao.Client) error {
				c.SetToken(validToken)
				err := c.SetAddress("https://localhost:" + port)
				if err != nil {
					return err
				}
				return c.ConfigureTLS(&openbao.TLSConfig{
					CACertBytes:     anotherCerts.caCertPEM,
					ClientCertBytes: anotherCerts.cliCertPEM,
					ClientKeyBytes:  anotherCerts.cliKeyPEM,
				})
			},
		)
		require.NoError(t, err)

		// when
		resp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: uuid.NewString(), Name: "Test Tenant"})

		// then
		require.Error(t, err)
		assert.Nil(t, resp)
	})
}

func TestPrepareTenant(t *testing.T) {
	// given
	ctx := t.Context()

	// start a container
	port := startOpenBao(t)

	cli, err := openbaovault.New(
		"test-client",
		func(c *openbao.Client) error {
			c.SetToken(validToken)
			return c.SetAddress("http://localhost:" + port)
		},
	)
	require.NoError(t, err)

	t.Run("should successfully prepare tenant", func(t *testing.T) {
		// given
		// when
		resp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: uuid.NewString(), Name: "Test Tenant"})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should be idempotent when preparing the same tenant", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()

		// first call to prepare tenant
		resp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// when
		// second call to prepare the same tenant
		resp, err = cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

func TestImportKey(t *testing.T) {
	// given
	ctx := t.Context()

	// start a container
	port := startOpenBao(t)

	cli, err := openbaovault.New(
		"test-client",
		func(c *openbao.Client) error {
			c.SetToken(validToken)
			return c.SetAddress("http://localhost:" + port)
		},
	)
	require.NoError(t, err)

	secretData, err := securemem.NewData("secret", 2)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := secretData.Destroy()
		assert.NoError(t, err)
	})
	copy(secretData.SecureBytes(), []byte("sm"))

	t.Run("should successfully import key", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// when
		resp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  "1",
			KeyMaterial: secretData,
			AAD:         []byte{4, 3, 2, 1},
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should successfully import key for nil aad", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// when
		resp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  "1",
			KeyMaterial: secretData,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should fail to import key with nil key material", func(t *testing.T) {
		// given
		// when
		resp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:   uuid.NewString(),
			KeyID:      uuid.NewString(),
			KeyVersion: "1",
			AAD:        []byte{4, 3, 2, 1},
		})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, vault.ErrInvalidRequest)
		assert.Nil(t, resp)
	})

	t.Run("should be idempotent when importing the same key", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// first call to import key
		resp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  "1",
			KeyMaterial: secretData,
			AAD:         []byte{4, 3, 2, 1},
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// when
		// second call to import the same key
		resp, err = cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  "1",
			KeyMaterial: secretData,
			AAD:         []byte{4, 3, 2, 1},
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should fail to import key for non-prepared tenant", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// when
		resp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  "1",
			KeyMaterial: secretData,
			AAD:         []byte{4, 3, 2, 1},
		})

		// then
		require.Error(t, err)
		assert.Nil(t, resp)
	})
}

func TestExportKey(t *testing.T) {
	// given
	ctx := t.Context()

	// start a container
	port := startOpenBao(t)

	cli, err := openbaovault.New(
		"test-client",
		func(c *openbao.Client) error {
			c.SetToken(validToken)
			return c.SetAddress("http://localhost:" + port)
		},
	)
	require.NoError(t, err)

	secretData, err := securemem.NewData("secret", 2)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := secretData.Destroy()
		assert.NoError(t, err)
	})
	copy(secretData.SecureBytes(), []byte("sm"))

	t.Run("should successfully export key", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// import key first
		iResp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  "1",
			KeyMaterial: secretData,
			AAD:         []byte{4, 3, 2, 1},
		})
		require.NoError(t, err)
		assert.NotNil(t, iResp)

		// when
		resp, err := cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, secretData.SecureBytes(), resp.KeyMaterial.SecureBytes())
		assert.Equal(t, []byte{4, 3, 2, 1}, resp.AAD)
	})

	t.Run("should successfully export key for nil aad", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// import key first
		iResp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  "1",
			KeyMaterial: secretData,
		})
		require.NoError(t, err)
		assert.NotNil(t, iResp)

		// when
		resp, err := cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, secretData.SecureBytes(), resp.KeyMaterial.SecureBytes())
		assert.Equal(t, []byte{}, resp.AAD)
	})

	t.Run("should fail to export key for non-prepared tenant", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// when
		resp, err := cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Nil(t, resp)
	})

	t.Run("should fail to export key for non-existing key", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// when
		resp, err := cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})

		// then
		require.Error(t, err)
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Nil(t, resp)
	})
}

func TestDestroyKey(t *testing.T) {
	// given
	ctx := t.Context()

	// start a container
	port := startOpenBao(t)

	cli, err := openbaovault.New(
		"test-client",
		func(c *openbao.Client) error {
			c.SetToken(validToken)
			return c.SetAddress("http://localhost:" + port)
		},
	)
	require.NoError(t, err)

	secretData, err := securemem.NewData("secret", 2)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := secretData.Destroy()
		assert.NoError(t, err)
	})
	copy(secretData.SecureBytes(), []byte("sm"))

	t.Run("should successfully destroy key version", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// import key first
		iResp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       keyID,
			KeyVersion:  "1",
			KeyMaterial: secretData,
			AAD:         []byte{4, 3, 2, 1},
		})
		require.NoError(t, err)
		assert.NotNil(t, iResp)

		// verify that the key version is saved
		eResp, err := cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})
		require.NoError(t, err)
		assert.NotNil(t, eResp)
		assert.Equal(t, secretData.SecureBytes(), eResp.KeyMaterial.SecureBytes())

		// when
		resp, err := cli.DestroyKey(ctx, vault.DestroyKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// verify that the key version is destroyed
		eResp, err = cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Nil(t, eResp)
	})

	t.Run("should not return error when destroying key version for non-prepared tenant", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// when
		resp, err := cli.DestroyKey(ctx, vault.DestroyKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should not return error when destroying key version for non-existing key", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		keyID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// when
		resp, err := cli.DestroyKey(ctx, vault.DestroyKeyRequest{
			TenantID:   tenantID,
			KeyID:      keyID,
			KeyVersion: "1",
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

func TestInfo(t *testing.T) {
	// given
	// start a container
	port := startOpenBao(t)

	cli, err := openbaovault.New(
		"test-client",
		func(c *openbao.Client) error {
			c.SetToken(validToken)
			return c.SetAddress("http://localhost:" + port)
		},
	)
	require.NoError(t, err)

	t.Run("should successfully get vault info", func(t *testing.T) {
		// when
		info := cli.Info()

		// then
		assert.Equal(t, "test-client", info.Name)
		assert.Equal(t, openbaovault.TypeOpenBao, info.Type)
	})
}

func TestDestroyTenant(t *testing.T) {
	// given
	ctx := t.Context()

	// start a container
	port := startOpenBao(t)

	cli, err := openbaovault.New(
		"test-client",
		func(c *openbao.Client) error {
			c.SetToken(validToken)
			return c.SetAddress("http://localhost:" + port)
		},
	)
	require.NoError(t, err)

	km, err := securemem.NewData("secret", 2)
	require.NoError(t, err)
	t.Cleanup(func() {
		err := km.Destroy()
		assert.NoError(t, err)
	})

	t.Run("should successfully destroy tenant with keys", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()
		kID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		iResp, err := cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID,
			KeyID:       kID,
			KeyVersion:  "1",
			KeyMaterial: km,
			AAD:         []byte{},
		})
		require.NoError(t, err)
		assert.NotNil(t, iResp)

		// when
		resp, err := cli.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: tenantID,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// verify that the tenant is destroyed
		_, err = cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID,
			KeyID:      kID,
			KeyVersion: "1",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
	})

	t.Run("should successfully destroy tenant with no keys", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// when
		resp, err := cli.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: tenantID,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should be idempotent when destroying the same tenant", func(t *testing.T) {
		// given
		tenantID := uuid.NewString()

		// prepare tenant first
		tResp, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID, Name: "Test Tenant"})
		require.NoError(t, err)
		assert.NotNil(t, tResp)

		// when
		resp, err := cli.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: tenantID,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// second call to destroy the same tenant
		resp, err = cli.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: tenantID,
		})

		require.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should not destroy other tenants when destroying a tenant", func(t *testing.T) {
		// given
		tenantID1 := uuid.NewString()
		tenantID2 := uuid.NewString()
		kID := uuid.NewString()

		// prepare tenant 1
		tResp1, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID1, Name: "Test Tenant 1"})
		require.NoError(t, err)
		assert.NotNil(t, tResp1)

		// import a key for tenant 1
		_, err = cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID1,
			KeyID:       kID,
			KeyVersion:  "1",
			KeyMaterial: km,
			AAD:         []byte{},
		})
		require.NoError(t, err)

		// prepare tenant 2
		tResp2, err := cli.PrepareTenant(ctx, vault.PrepareTenantRequest{TenantID: tenantID2, Name: "Test Tenant 2"})
		require.NoError(t, err)
		assert.NotNil(t, tResp2)

		// import a key for tenant 2
		_, err = cli.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    tenantID2,
			KeyID:       kID,
			KeyVersion:  "1",
			KeyMaterial: km,
			AAD:         []byte{},
		})
		require.NoError(t, err)

		// when
		resp, err := cli.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: tenantID1,
		})

		// then
		require.NoError(t, err)
		assert.NotNil(t, resp)

		// verify that tenant 1 is destroyed
		eRep, err := cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID1,
			KeyID:      kID,
			KeyVersion: "1",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Nil(t, eRep)

		// verify that tenant 2 is still accessible
		eRep, err = cli.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   tenantID2,
			KeyID:      kID,
			KeyVersion: "1",
		})
		require.NoError(t, err)
		assert.NotNil(t, eRep)
		assert.Equal(t, km.SecureBytes(), eRep.KeyMaterial.SecureBytes())
	})
}

func startOpenBao(t *testing.T) string {
	t.Helper()

	ctx := t.Context()

	container, err := testcontainers.Run(
		ctx,
		"ghcr.io/openbao/openbao",
		testcontainers.WithCmdArgs("server", "-dev", "-dev-root-token-id="+validToken),
		testcontainers.WithExposedPorts("8200"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Development mode should NOT be used in production installations!"),
			wait.ForListeningPort("8200/tcp"),
		),
	)
	require.NoError(t, err)

	testcontainers.CleanupContainer(t, container)

	np, err := container.MappedPort(ctx, "8200")
	require.NoError(t, err)
	return np.Port()
}

func startOpenBaoWithMTLS(t *testing.T, certs *tlsCerts) string {
	t.Helper()

	ctx := t.Context()

	container, err := testcontainers.Run(
		ctx,
		"ghcr.io/openbao/openbao",
		testcontainers.WithCmdArgs("server", "-dev", "-dev-root-token-id="+validToken, "-config=/vault/config/openbao.hcl"),
		testcontainers.WithEnv(map[string]string{
			"SKIP_SETCAP": "true",
		}),
		testcontainers.WithExposedPorts("8300"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("Development mode should NOT be used in production installations!"),
			wait.ForListeningPort("8300/tcp"),
		),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				ContainerFilePath: "/vault/certs/ca.crt",
				Reader:            bytes.NewReader(certs.caCertPEM),
				FileMode:          0o644,
			},
			testcontainers.ContainerFile{
				ContainerFilePath: "/vault/certs/server.crt",
				Reader:            bytes.NewReader(certs.srvCertPEM),
				FileMode:          0o644,
			},
			testcontainers.ContainerFile{
				ContainerFilePath: "/vault/certs/server.key",
				Reader:            bytes.NewReader(certs.srvKeyPEM),
				FileMode:          0o644,
			},
			testcontainers.ContainerFile{
				ContainerFilePath: "/vault/config/openbao.hcl",
				Reader:            bytes.NewReader([]byte(openbaoHCLConfig())),
				FileMode:          0o644,
			},
		),
	)
	require.NoError(t, err)

	testcontainers.CleanupContainer(t, container)

	np, err := container.MappedPort(ctx, "8300")
	require.NoError(t, err)
	return np.Port()
}

func openbaoHCLConfig() string {
	return `
storage "inmem" {}

listener "tcp" {
    address       = "0.0.0.0:8400"
    tls_disable   = true
}

listener "tcp" {
  address                            = "0.0.0.0:8300"
  tls_cert_file                      = "/vault/certs/server.crt"
  tls_key_file                       = "/vault/certs/server.key"
  tls_client_ca_file                 = "/vault/certs/ca.crt"
  tls_require_and_verify_client_cert = true
}

api_addr      = "https://0.0.0.0:8300"
disable_mlock = true
`
}

func generateCerts(t *testing.T) *tlsCerts {
	t.Helper()

	// create ca keys and certs
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "OpenBao CA",
			Organization: []string{"Test Organization"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	// create server keys and certs
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"Test Organization"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"localhost"},
	}

	srvCertDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	require.NoError(t, err)

	srvCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvCertDER})

	srvKeyDER, err := x509.MarshalECPrivateKey(srvKey)
	require.NoError(t, err)

	srvKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: srvKeyDER})

	// create client keys and certs
	cliKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cliKeyDER, err := x509.MarshalECPrivateKey(cliKey)
	require.NoError(t, err)
	cliKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: cliKeyDER})

	cliTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   "client",
			Organization: []string{"Test Organization"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(1 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	cliCertDER, err := x509.CreateCertificate(rand.Reader, cliTmpl, caTmpl, &cliKey.PublicKey, caKey)
	require.NoError(t, err)

	cliCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cliCertDER})

	return &tlsCerts{
		caCertPEM:  caCertPEM,
		srvCertPEM: srvCertPEM,
		srvKeyPEM:  srvKeyPEM,
		cliCertPEM: cliCertPEM,
		cliKeyPEM:  cliKeyPEM,
	}
}
