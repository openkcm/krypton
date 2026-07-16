package sqlitevault_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
)

func newTestUnsafeVault(t *testing.T) *sqlitevault.Unsafe {
	t.Helper()
	v, err := sqlitevault.NewUnsafe(t.Context(), "test", sqlitevault.MemorySource)
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = v.Close()
	})
	return v
}

func newTestSecureData(t *testing.T, data []byte) *securemem.Data {
	t.Helper()
	d, err := securemem.NewData("test-key", len(data))
	assert.NoError(t, err)
	copy(d.SecureBytes(), data)
	t.Cleanup(func() {
		_ = d.Destroy()
	})
	return d
}

func TestUnsafe_ImportAndExportKey(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()
	keyBytes := []byte("this-is-a-32-byte-test-key-mat!")
	aad := []byte("additional-authenticated-data")

	// when
	_, err := v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    "tenant-1",
		KeyID:       "key-1",
		KeyVersion:  "1",
		KeyMaterial: newTestSecureData(t, keyBytes),
		AAD:         aad,
	})

	// then
	assert.NoError(t, err)

	// when
	resp, err := v.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID:   "tenant-1",
		KeyID:      "key-1",
		KeyVersion: "1",
	})

	// then
	assert.NoError(t, err)
	assert.Equal(t, keyBytes, []byte(resp.KeyMaterial.SecureBytes()))
	assert.Equal(t, aad, resp.AAD)
	_ = resp.KeyMaterial.Destroy()
}

func TestUnsafe_ImportKeyErrors(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	_, err := v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    "tenant-1",
		KeyID:       "key-1",
		KeyVersion:  "1",
		KeyMaterial: newTestSecureData(t, []byte("key-material-32-bytes-padding!!")),
	})
	assert.NoError(t, err)

	tests := []struct {
		name string
		req  vault.ImportKeyRequest
	}{
		{
			name: "empty tenant ID",
			req: vault.ImportKeyRequest{
				TenantID:    "",
				KeyID:       "key-1",
				KeyVersion:  "1",
				KeyMaterial: newTestSecureData(t, []byte("key-material-32-bytes-padding!!")),
			},
		},
		{
			name: "empty key ID",
			req: vault.ImportKeyRequest{
				TenantID:    "tenant-1",
				KeyID:       "",
				KeyVersion:  "1",
				KeyMaterial: newTestSecureData(t, []byte("key-material-32-bytes-padding!!")),
			},
		},
		{
			name: "duplicate key version",
			req: vault.ImportKeyRequest{
				TenantID:    "tenant-1",
				KeyID:       "key-1",
				KeyVersion:  "1",
				KeyMaterial: newTestSecureData(t, []byte("key-material-32-bytes-padding!!")),
			},
		},
		{
			name: "nil key material",
			req: vault.ImportKeyRequest{
				TenantID:   "tenant-1",
				KeyID:      "key-2",
				KeyVersion: "1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.ImportKey(ctx, tt.req)
			assert.Error(t, err)
		})
	}
}

func TestUnsafe_ExportKeyLatestVersion(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	versions := []struct {
		version string
		data    []byte
	}{
		{"1", []byte("key-material-version-1-padding!")},
		{"2", []byte("key-material-version-2-padding!")},
		{"3", []byte("key-material-version-3-padding!")},
	}

	for _, ver := range versions {
		_, err := v.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    "tenant-1",
			KeyID:       "key-1",
			KeyVersion:  ver.version,
			KeyMaterial: newTestSecureData(t, ver.data),
			AAD:         []byte("aad"),
		})
		assert.NoError(t, err)
	}

	// when
	resp, err := v.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID:   "tenant-1",
		KeyID:      "key-1",
		KeyVersion: versions[2].version,
	})

	// then
	assert.NoError(t, err)
	assert.Equal(t, versions[2].data, []byte(resp.KeyMaterial.SecureBytes()))
	_ = resp.KeyMaterial.Destroy()
}

func TestUnsafe_ExportKeySpecificVersion(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	v1Data := []byte("key-material-version-1-padding!")
	v2Data := []byte("key-material-version-2-padding!")

	_, err := v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    "tenant-1",
		KeyID:       "key-1",
		KeyVersion:  "1",
		KeyMaterial: newTestSecureData(t, v1Data),
		AAD:         []byte("aad-v1"),
	})
	assert.NoError(t, err)

	_, err = v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    "tenant-1",
		KeyID:       "key-1",
		KeyVersion:  "2",
		KeyMaterial: newTestSecureData(t, v2Data),
		AAD:         []byte("aad-v2"),
	})
	assert.NoError(t, err)

	// when
	resp, err := v.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID:   "tenant-1",
		KeyID:      "key-1",
		KeyVersion: "1",
	})

	// then
	assert.NoError(t, err)
	assert.Equal(t, v1Data, []byte(resp.KeyMaterial.SecureBytes()))
	assert.Equal(t, []byte("aad-v1"), resp.AAD)
	_ = resp.KeyMaterial.Destroy()
}

func TestUnsafe_ExportKeyNotFound(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	// when
	resp, err := v.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID:   "tenant-1",
		KeyID:      "key-1",
		KeyVersion: "1",
	})

	// then
	assert.ErrorIs(t, err, vault.ErrKeyNotFound)
	assert.Nil(t, resp)
}

func TestUnsafe_DestroyKey(t *testing.T) {
	// given
	v := newTestUnsafeVault(t)
	ctx := t.Context()

	v1Data := []byte("key-material-version-1-padding!")
	v2Data := []byte("key-material-version-2-padding!")

	_, err := v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    "tenant-1",
		KeyID:       "key-1",
		KeyVersion:  "1",
		KeyMaterial: newTestSecureData(t, v1Data),
	})
	assert.NoError(t, err)

	_, err = v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    "tenant-1",
		KeyID:       "key-1",
		KeyVersion:  "2",
		KeyMaterial: newTestSecureData(t, v2Data),
	})
	assert.NoError(t, err)

	// when
	_, err = v.DestroyKey(ctx, vault.DestroyKeyRequest{
		TenantID:   "tenant-1",
		KeyID:      "key-1",
		KeyVersion: "1",
	})

	// then
	assert.NoError(t, err)

	resp, err := v.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID:   "tenant-1",
		KeyID:      "key-1",
		KeyVersion: "1",
	})
	assert.ErrorIs(t, err, vault.ErrKeyNotFound)
	assert.Nil(t, resp)

	// v2 should still exist
	resp, err = v.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID:   "tenant-1",
		KeyID:      "key-1",
		KeyVersion: "2",
	})
	assert.NoError(t, err)
	assert.Equal(t, v2Data, []byte(resp.KeyMaterial.SecureBytes()))
	_ = resp.KeyMaterial.Destroy()
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
		assert.NoError(t, err)
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
	keyBytes := []byte("persistent-key-material-32byte!")
	aad := []byte("persistent-aad")

	v, err := sqlitevault.NewUnsafe(ctx, "persist-test", sqlitevault.FileSource(dbPath))
	assert.NoError(t, err)

	_, err = v.ImportKey(ctx, vault.ImportKeyRequest{
		TenantID:    "tenant-1",
		KeyID:       "key-1",
		KeyVersion:  "1",
		KeyMaterial: newTestSecureData(t, keyBytes),
		AAD:         aad,
	})
	assert.NoError(t, err)
	assert.NoError(t, v.Close())

	// when - reopen the same file source
	v2, err := sqlitevault.NewUnsafe(ctx, "persist-test", sqlitevault.FileSource(dbPath))
	assert.NoError(t, err)
	t.Cleanup(func() {
		_ = v2.Close()
	})

	// then
	resp, err := v2.ExportKey(ctx, vault.ExportKeyRequest{
		TenantID:   "tenant-1",
		KeyID:      "key-1",
		KeyVersion: "1",
	})
	assert.NoError(t, err)
	assert.Equal(t, keyBytes, []byte(resp.KeyMaterial.SecureBytes()))
	assert.Equal(t, aad, resp.AAD)
	_ = resp.KeyMaterial.Destroy()
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

	t.Run("destroy tenant with keys", func(t *testing.T) {
		// given
		_, err := v.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    "tenant-1",
			KeyID:       "key-1",
			KeyVersion:  "1",
			KeyMaterial: newTestSecureData(t, []byte("key-material")),
		})
		assert.NoError(t, err)

		// when
		resp, err := v.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: "tenant-1",
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// verify keys are deleted
		exportResp, err := v.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
		})
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Nil(t, exportResp)
	})

	t.Run("destroy tenant without keys", func(t *testing.T) {
		// when
		resp, err := v.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: "tenant-2",
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)
	})

	t.Run("should destroy only keys of the specified tenant", func(t *testing.T) {
		// given
		_, err := v.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    "tenant-1",
			KeyID:       "key-1",
			KeyVersion:  "1",
			KeyMaterial: newTestSecureData(t, []byte("key-material-1")),
		})
		assert.NoError(t, err)

		_, err = v.ImportKey(ctx, vault.ImportKeyRequest{
			TenantID:    "tenant-2",
			KeyID:       "key-2",
			KeyVersion:  "1",
			KeyMaterial: newTestSecureData(t, []byte("key-material-2")),
		})
		assert.NoError(t, err)

		// when
		resp, err := v.DestroyTenant(ctx, vault.DestroyTenantRequest{
			TenantID: "tenant-1",
		})

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)

		// verify keys of tenant-1 are deleted
		exportResp1, err := v.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
		})
		assert.ErrorIs(t, err, vault.ErrKeyNotFound)
		assert.Nil(t, exportResp1)

		// verify keys of tenant-2 still exist
		exportResp2, err := v.ExportKey(ctx, vault.ExportKeyRequest{
			TenantID:   "tenant-2",
			KeyID:      "key-2",
			KeyVersion: "1",
		})
		assert.NoError(t, err)
		assert.Equal(t, []byte("key-material-2"), []byte(exportResp2.KeyMaterial.SecureBytes()))
		_ = exportResp2.KeyMaterial.Destroy()
	})
}
