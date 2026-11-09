package sqlitevault_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
)

func newTestUnsafeVault(t *testing.T) *sqlitevault.Unsafe {
	t.Helper()
	v, err := sqlitevault.NewUnsafe(t.Context(), "test", sqlitevault.MemorySource)
	require.NoError(t, err)
	require.NotNil(t, v)
	t.Cleanup(func() {
		_ = v.Close()
	})
	return v
}

func newTestSecureData(t *testing.T, data []byte) *securemem.Data {
	t.Helper()
	d, err := securemem.NewData("test-secret", len(data))
	require.NoError(t, err)
	copy(d.SecureBytes(), data)
	t.Cleanup(func() {
		_ = d.Destroy()
	})
	return d
}

func TestUnsafe_ImportAndExportSecret(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()
	secretBytes := []byte("this-is-a-test-secret")
	metadata := []byte("metadata")

	// when
	_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Secret:   newTestSecureData(t, secretBytes),
		Metadata: metadata,
	})

	// then
	assert.NoError(t, err)

	// when
	resp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
	})

	// then
	assert.NoError(t, err)
	assert.Equal(t, secretBytes, []byte(resp.Secret.SecureBytes()))
	assert.Equal(t, metadata, resp.Metadata)
	_ = resp.Secret.Destroy()
}

func TestUnsafe_ImportSecretErrors(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Secret:   newTestSecureData(t, []byte("secret")),
	})
	assert.NoError(t, err)

	tests := []struct {
		name string
		req  vault.ImportSecretRequest
	}{
		{
			name: "empty tenant ID",
			req: vault.ImportSecretRequest{
				TenantID: "",
				ID:       "secret-1",
				Version:  1,
				Secret:   newTestSecureData(t, []byte("secret")),
			},
		},
		{
			name: "empty secret ID",
			req: vault.ImportSecretRequest{
				TenantID: "tenant-1",
				ID:       "",
				Version:  1,
				Secret:   newTestSecureData(t, []byte("secret")),
			},
		},
		{
			name: "nil secret",
			req: vault.ImportSecretRequest{
				TenantID: "tenant-1",
				ID:       "secret-2",
				Version:  1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.ImportSecret(ctx, tt.req)
			assert.Error(t, err)
		})
	}
}

func TestUnsafe_ImportDuplicateSecret(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	secret1 := newTestSecureData(t, []byte("secret-1"))
	secret2 := newTestSecureData(t, []byte("secret-2"))
	metadata1 := []byte("metadata-1")
	metadata2 := []byte("metadata-2")

	_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 1,
		Secret:   secret1,
		Metadata: metadata1,
	})
	assert.NoError(t, err)

	exported1, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 1,
	})
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = exported1.Secret.Destroy()
	})

	// when - import the same secret again
	_, err = v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 1,
		Secret:   secret2,
		Metadata: metadata2,
	})
	assert.NoError(t, err) // In this unsafe implementation, importing a duplicate secret overwrites the existing one.

	exported2, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 1,
	})

	// then
	assert.NoError(t, err)

	t.Cleanup(func() {
		_ = exported2.Secret.Destroy()
	})

	assert.NotEqual(t, exported1.Secret.SecureBytes(), exported2.Secret.SecureBytes())
	assert.Equal(t, secret1.SecureBytes(), exported1.Secret.SecureBytes())
	assert.Equal(t, secret2.SecureBytes(), exported2.Secret.SecureBytes())
	assert.NotEqual(t, exported1.Metadata, exported2.Metadata)
	assert.Equal(t, metadata1, exported1.Metadata)
	assert.Equal(t, metadata2, exported2.Metadata)
}

func TestUnsafe_ExportSecretLatestVersion(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	versions := []struct {
		version int
		data    []byte
	}{
		{1, []byte("secret-version-1")},
		{2, []byte("secret-version-2")},
		{3, []byte("secret-version-3")},
	}

	for _, ver := range versions {
		_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
			TenantID: "tenant-1",
			ID:       "secret-1",
			Version:  ver.version,
			Secret:   newTestSecureData(t, ver.data),
			Metadata: []byte("metadata"),
		})
		assert.NoError(t, err)
	}

	// when
	resp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  versions[2].version,
	})

	// then
	assert.NoError(t, err)
	assert.Equal(t, versions[2].data, []byte(resp.Secret.SecureBytes()))
	_ = resp.Secret.Destroy()
}

func TestUnsafe_ExportSecretSpecificVersion(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	v1Data := []byte("secret-version-1")
	v2Data := []byte("secret-version-2")

	_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Secret:   newTestSecureData(t, v1Data),
		Metadata: []byte("metadata-v1"),
	})
	assert.NoError(t, err)

	_, err = v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  2,
		Secret:   newTestSecureData(t, v2Data),
		Metadata: []byte("metadata-v2"),
	})
	assert.NoError(t, err)

	// when
	resp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
	})

	// then
	assert.NoError(t, err)
	assert.Equal(t, v1Data, []byte(resp.Secret.SecureBytes()))
	assert.Equal(t, []byte("metadata-v1"), resp.Metadata)
	_ = resp.Secret.Destroy()
}

func TestUnsafe_ExportSecretNotFound(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	// when
	resp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
	})

	// then
	assert.ErrorIs(t, err, vault.ErrSecretNotFound)
	assert.Nil(t, resp)
}

func TestUnsafe_DestroySecret(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	v1Data := []byte("secret-version-1")
	v2Data := []byte("secret-version-2")

	_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Secret:   newTestSecureData(t, v1Data),
	})
	assert.NoError(t, err)

	_, err = v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  2,
		Secret:   newTestSecureData(t, v2Data),
	})
	assert.NoError(t, err)

	// when
	_, err = v.DestroySecret(ctx, vault.DestroySecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
	})

	// then
	assert.NoError(t, err)

	resp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
	})
	assert.ErrorIs(t, err, vault.ErrSecretNotFound)
	assert.Nil(t, resp)

	// v2 should still exist
	resp, err = v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  2,
	})
	assert.NoError(t, err)
	assert.Equal(t, v2Data, []byte(resp.Secret.SecureBytes()))
	_ = resp.Secret.Destroy()
}

func TestUnsafe_RevisionCoexistence(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	rev0Data := []byte("secret-revision-0")
	rev1Data := []byte("secret-revision-1")

	_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 0,
		Secret:   newTestSecureData(t, rev0Data),
		Metadata: []byte("metadata-rev-0"),
	})
	assert.NoError(t, err)

	_, err = v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 1,
		Secret:   newTestSecureData(t, rev1Data),
		Metadata: []byte("metadata-rev-1"),
	})
	assert.NoError(t, err)

	// when - export revision 0
	resp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 0,
	})

	// then
	assert.NoError(t, err)
	assert.Equal(t, rev0Data, []byte(resp.Secret.SecureBytes()))
	assert.Equal(t, []byte("metadata-rev-0"), resp.Metadata)
	_ = resp.Secret.Destroy()

	// when - export revision 1
	resp, err = v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 1,
	})

	// then
	assert.NoError(t, err)
	assert.Equal(t, rev1Data, []byte(resp.Secret.SecureBytes()))
	assert.Equal(t, []byte("metadata-rev-1"), resp.Metadata)
	_ = resp.Secret.Destroy()

	// when - destroy revision 0 only
	_, err = v.DestroySecret(ctx, vault.DestroySecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 0,
	})
	assert.NoError(t, err)

	// then - revision 0 is gone
	resp, err = v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 0,
	})
	assert.ErrorIs(t, err, vault.ErrSecretNotFound)
	assert.Nil(t, resp)

	// then - revision 1 still exists
	resp, err = v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Revision: 1,
	})
	assert.NoError(t, err)
	assert.Equal(t, rev1Data, []byte(resp.Secret.SecureBytes()))
	_ = resp.Secret.Destroy()
}

func TestUnsafe_Info(t *testing.T) {
	t.Run("memory source", func(t *testing.T) {
		// given
		v := newTestUnsafeVault(t)

		// when
		info := v.Info()

		// then
		assert.Equal(t, "test", info.Name)
		assert.Equal(t, sqlitevault.TypeUnsafeMemory, info.Type)
	})

	t.Run("file source", func(t *testing.T) {
		// given
		dbPath := filepath.Join(t.TempDir(), "test.db")
		v, err := sqlitevault.NewUnsafe(t.Context(), "file-vault", sqlitevault.FileSource(dbPath))
		require.NoError(t, err)
		t.Cleanup(func() {
			_ = v.Close()
		})

		// when
		info := v.Info()

		// then
		assert.Equal(t, "file-vault", info.Name)
		assert.Equal(t, sqlitevault.TypeUnsafe, info.Type)
	})
}

func TestUnsafe_FileSourcePersistence(t *testing.T) {
	// given
	dbPath := filepath.Join(t.TempDir(), "persistent.db")
	ctx := t.Context()
	secretBytes := []byte("persistent-secret")
	metadata := []byte("persistent-metadata")

	v, err := sqlitevault.NewUnsafe(ctx, "persist-test", sqlitevault.FileSource(dbPath))
	require.NoError(t, err)

	_, err = v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
		Secret:   newTestSecureData(t, secretBytes),
		Metadata: metadata,
	})
	require.NoError(t, err)
	assert.NoError(t, v.Close())

	// when - reopen the same file source
	v2, err := sqlitevault.NewUnsafe(ctx, "persist-test", sqlitevault.FileSource(dbPath))
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = v2.Close()
	})

	// then
	resp, err := v2.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: "tenant-1",
		ID:       "secret-1",
		Version:  1,
	})
	assert.NoError(t, err)
	assert.Equal(t, secretBytes, []byte(resp.Secret.SecureBytes()))
	assert.Equal(t, metadata, resp.Metadata)
	_ = resp.Secret.Destroy()
}

func TestPrepareTenant(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	// when
	resp, err := v.PrepareTenant(ctx, vault.PrepareTenantRequest{
		TenantID: "tenant-1",
		Name:     "Test Tenant",
	})

	// then
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestDestroyTenant(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	t.Run("destroy tenant with secrets", func(t *testing.T) {
		// given
		_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
			TenantID: "tenant-1",
			ID:       "secret-1",
			Version:  1,
			Secret:   newTestSecureData(t, []byte("secret")),
		})
		assert.NoError(t, err)

		// when
		resp, err := v.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: "tenant-1",
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// verify secrets are deleted
		exportResp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
			TenantID: "tenant-1",
			ID:       "secret-1",
			Version:  1,
		})
		assert.ErrorIs(t, err, vault.ErrSecretNotFound)
		assert.Nil(t, exportResp)
	})

	t.Run("destroy tenant without secrets", func(t *testing.T) {
		// when
		resp, err := v.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: "tenant-2",
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should destroy only secrets of the specified tenant", func(t *testing.T) {
		// given
		_, err := v.ImportSecret(ctx, vault.ImportSecretRequest{
			TenantID: "tenant-1",
			ID:       "secret-1",
			Version:  1,
			Secret:   newTestSecureData(t, []byte("secret-1")),
		})
		assert.NoError(t, err)

		_, err = v.ImportSecret(ctx, vault.ImportSecretRequest{
			TenantID: "tenant-2",
			ID:       "secret-2",
			Version:  1,
			Secret:   newTestSecureData(t, []byte("secret-2")),
		})
		assert.NoError(t, err)

		// when
		resp, err := v.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: "tenant-1",
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// verify secrets of tenant-1 are deleted
		exportResp1, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
			TenantID: "tenant-1",
			ID:       "secret-1",
			Version:  1,
		})
		assert.ErrorIs(t, err, vault.ErrSecretNotFound)
		assert.Nil(t, exportResp1)

		// verify secrets of tenant-2 still exist
		exportResp2, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
			TenantID: "tenant-2",
			ID:       "secret-2",
			Version:  1,
		})
		assert.NoError(t, err)
		assert.Equal(t, []byte("secret-2"), []byte(exportResp2.Secret.SecureBytes()))
		_ = exportResp2.Secret.Destroy()
	})
}
