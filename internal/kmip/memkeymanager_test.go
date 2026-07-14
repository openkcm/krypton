package kmip_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/pkg/model"
)

func newTestMem(t *testing.T, seeds ...kmip.SeedDEK) kmip.KeyManager {
	t.Helper()
	km, err := kmip.NewMemKeyManager(seeds...)
	require.NoError(t, err, "NewMemKeyManager")
	t.Cleanup(func() {
		if c, ok := km.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	})
	return km
}

func TestMemKeyManager_GetDEK(t *testing.T) {
	t.Parallel()
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(i)
	}
	km := newTestMem(t,
		kmip.SeedDEK{
			TenantID: "tenant-a", KeyID: "dek-1", Material: material,
			Algorithm: kmip.AlgorithmAES, LengthBits: 256, State: model.KeyLifeCycleActive,
		},
		kmip.SeedDEK{
			TenantID: "tenant-a", KeyID: "pre", Material: []byte{1, 2, 3, 4},
			Algorithm: kmip.AlgorithmAES, LengthBits: 32, State: model.KeyLifeCyclePreActivation,
		},
		kmip.SeedDEK{
			TenantID: "tenant-a", KeyID: "destroyed", Material: []byte{9, 9, 9, 9},
			Algorithm: kmip.AlgorithmAES, LengthBits: 32, State: model.KeyLifeCycleDestroyed,
		},
	)
	ctx := context.Background()

	t.Run("happy path", func(t *testing.T) {
		got, err := km.GetDEK(ctx, "tenant-a", "dek-1")
		require.NoError(t, err)
		assert.Equal(t, int32(256), got.LengthBits)
		assert.Equal(t, kmip.AlgorithmAES, got.Algorithm)
		assert.Equal(t, model.KeyLifeCycleActive, got.State)
		bytes := got.Material.SecureBytes()
		require.Len(t, bytes, 32)
		assert.Equal(t, byte(0), bytes[0])
		assert.Equal(t, byte(31), bytes[31])
	})

	t.Run("not found", func(t *testing.T) {
		_, err := km.GetDEK(ctx, "tenant-a", "missing")
		assert.ErrorIs(t, err, kmip.ErrKeyNotFound)
	})

	t.Run("destroyed is not found", func(t *testing.T) {
		_, err := km.GetDEK(ctx, "tenant-a", "destroyed")
		assert.ErrorIs(t, err, kmip.ErrKeyNotFound)
	})

	t.Run("pre-activation is not active", func(t *testing.T) {
		_, err := km.GetDEK(ctx, "tenant-a", "pre")
		assert.ErrorIs(t, err, kmip.ErrKeyNotActive)
	})

	t.Run("wrong tenant is not found", func(t *testing.T) {
		_, err := km.GetDEK(ctx, "tenant-b", "dek-1")
		assert.ErrorIs(t, err, kmip.ErrKeyNotFound)
	})
}

func TestMemKeyManager_GetKeyInfo(t *testing.T) {
	t.Parallel()
	km := newTestMem(t, kmip.SeedDEK{
		TenantID: "tenant-a", KeyID: "dek-1", Material: []byte("0123456789abcdef0123456789abcdef"),
		Algorithm: kmip.AlgorithmAES, LengthBits: 256, State: model.KeyLifeCycleActive,
	})
	info, err := km.GetKeyInfo(context.Background(), "tenant-a", "dek-1")
	require.NoError(t, err)
	assert.Equal(t, int32(256), info.LengthBits)
	assert.Equal(t, kmip.AlgorithmAES, info.Algorithm)
}

func TestMemKeyManager_SeedValidation(t *testing.T) {
	t.Parallel()
	_, err := kmip.NewMemKeyManager(kmip.SeedDEK{TenantID: "", KeyID: "k", Material: []byte("x")})
	assert.Error(t, err, "expected error for empty tenant")
	_, err = kmip.NewMemKeyManager(kmip.SeedDEK{TenantID: "t", KeyID: "", Material: []byte("x")})
	assert.Error(t, err, "expected error for empty key ID")
	_, err = kmip.NewMemKeyManager(kmip.SeedDEK{TenantID: "t", KeyID: "k", Material: nil})
	assert.Error(t, err, "expected error for empty material")
}
