package kmip

import (
	"context"
	"errors"
	"testing"

	"github.com/openkcm/krypton/pkg/model"
)

func newTestMem(t *testing.T, seeds ...SeedDEK) KeyManager {
	t.Helper()
	km, err := NewMemKeyManager(seeds...)
	if err != nil {
		t.Fatalf("NewMemKeyManager: %v", err)
	}
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
		SeedDEK{
			TenantID: "tenant-a", KeyID: "dek-1", Material: material,
			Algorithm: AlgorithmAES, LengthBits: 256, State: model.KeyLifeCycleActive,
		},
		SeedDEK{
			TenantID: "tenant-a", KeyID: "pre", Material: []byte{1, 2, 3, 4},
			Algorithm: AlgorithmAES, LengthBits: 32, State: model.KeyLifeCyclePreActivation,
		},
		SeedDEK{
			TenantID: "tenant-a", KeyID: "destroyed", Material: []byte{9, 9, 9, 9},
			Algorithm: AlgorithmAES, LengthBits: 32, State: model.KeyLifeCycleDestroyed,
		},
	)
	ctx := context.Background()

	t.Run("happy path", func(t *testing.T) {
		got, err := km.GetDEK(ctx, "tenant-a", "dek-1")
		if err != nil {
			t.Fatalf("GetDEK: %v", err)
		}
		if got.LengthBits != 256 || got.Algorithm != AlgorithmAES {
			t.Fatalf("metadata mismatch: %+v", got)
		}
		if got.State != model.KeyLifeCycleActive {
			t.Fatalf("state = %v, want Active", got.State)
		}
		if bytes := got.Material.SecureBytes(); len(bytes) != 32 || bytes[0] != 0 || bytes[31] != 31 {
			t.Fatalf("material mismatch len=%d", len(bytes))
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := km.GetDEK(ctx, "tenant-a", "missing")
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("destroyed is not found", func(t *testing.T) {
		_, err := km.GetDEK(ctx, "tenant-a", "destroyed")
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
	})

	t.Run("pre-activation is not active", func(t *testing.T) {
		_, err := km.GetDEK(ctx, "tenant-a", "pre")
		if !errors.Is(err, ErrKeyNotActive) {
			t.Fatalf("err = %v, want ErrKeyNotActive", err)
		}
	})

	t.Run("wrong tenant is not found", func(t *testing.T) {
		_, err := km.GetDEK(ctx, "tenant-b", "dek-1")
		if !errors.Is(err, ErrKeyNotFound) {
			t.Fatalf("err = %v, want ErrKeyNotFound", err)
		}
	})
}

func TestMemKeyManager_GetKeyInfo(t *testing.T) {
	t.Parallel()
	km := newTestMem(t, SeedDEK{
		TenantID: "tenant-a", KeyID: "dek-1", Material: []byte("0123456789abcdef0123456789abcdef"),
		Algorithm: AlgorithmAES, LengthBits: 256, State: model.KeyLifeCycleActive,
	})
	info, err := km.GetKeyInfo(context.Background(), "tenant-a", "dek-1")
	if err != nil {
		t.Fatalf("GetKeyInfo: %v", err)
	}
	if info.LengthBits != 256 || info.Algorithm != AlgorithmAES {
		t.Fatalf("info mismatch: %+v", info)
	}
}

func TestMemKeyManager_SeedValidation(t *testing.T) {
	t.Parallel()
	if _, err := NewMemKeyManager(SeedDEK{TenantID: "", KeyID: "k", Material: []byte("x")}); err == nil {
		t.Fatal("expected error for empty tenant")
	}
	if _, err := NewMemKeyManager(SeedDEK{TenantID: "t", KeyID: "", Material: []byte("x")}); err == nil {
		t.Fatal("expected error for empty key ID")
	}
	if _, err := NewMemKeyManager(SeedDEK{TenantID: "t", KeyID: "k", Material: nil}); err == nil {
		t.Fatal("expected error for empty material")
	}
}
