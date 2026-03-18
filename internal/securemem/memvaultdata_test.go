package securemem_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/securemem"
)

func TestNewWithSize(t *testing.T) {
	t.Run("should create vault with specified size", func(t *testing.T) {
		// given when
		subj, err := securemem.NewMemVaultData("test-region", 64)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// then
		data := subj.Data()
		assert.Len(t, data, 64)

		// mmap'd anonymous memory should be zeroed
		for _, b := range data {
			assert.Equal(t, byte(0), b)
		}
	})

	t.Run("should return error for invalid sizes", func(t *testing.T) {
		tts := []struct {
			name string
			size int
		}{
			{name: "negative size", size: -1},
			{name: "zero size", size: 0},
		}

		for _, tt := range tts {
			t.Run("for "+tt.name, func(t *testing.T) {
				// given when
				subj, err := securemem.NewMemVaultData("test-"+tt.name, tt.size)

				// then
				assert.ErrorIs(t, err, securemem.ErrInvalidSize)
				assert.Nil(t, subj)
			})
		}
	})

	t.Run("should write data and read it back", func(t *testing.T) {
		// given
		secret := []byte("my-secret-key-1234567890")
		subj, err := securemem.NewMemVaultData("test-roundtrip", len(secret))
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// when
		copy(subj.Data(), secret)

		// then
		assert.Equal(t, secret, subj.Data())
	})

	t.Run("should allocate larger sizes", func(t *testing.T) {
		// given
		expectedSize := 5000

		// when
		subj, err := securemem.NewMemVaultData("test-large-region", expectedSize)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// then
		data := subj.Data()
		assert.Len(t, data, expectedSize)

		for _, b := range data {
			assert.Equal(t, byte(0), b)
		}
	})
}

func TestDestroy(t *testing.T) {
	t.Run("should securely destroy vault data", func(t *testing.T) {
		// given
		subj, err := securemem.NewMemVaultData("test-destroy", 128)
		require.NoError(t, err)

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)
		assert.Nil(t, subj.Data())
	})

	t.Run("should be idempotent", func(t *testing.T) {
		// given
		subj, err := securemem.NewMemVaultData("test-idempotent", 64)
		require.NoError(t, err)

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)
		assert.Nil(t, subj.Data())
	})
}

func TestReadonly(t *testing.T) {
	t.Run("should set vault to readonly mode", func(t *testing.T) {
		// given
		subj, err := securemem.NewMemVaultData("test-readonly", 40)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// when
		err = subj.MarkReadOnly()

		// then
		assert.NoError(t, err)
		assert.True(t, subj.IsReadOnly())
	})

	t.Run("should be idempotent", func(t *testing.T) {
		// given
		subj, err := securemem.NewMemVaultData("test-readonly-idempotent", 40)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// when
		err = subj.MarkReadOnly()

		// then
		assert.NoError(t, err)
		assert.True(t, subj.IsReadOnly())

		// when
		err = subj.MarkReadOnly()

		// then
		assert.NoError(t, err)
		assert.True(t, subj.IsReadOnly())
	})

	t.Run("should destroy vault even if readonly", func(t *testing.T) {
		// given
		subj, err := securemem.NewMemVaultData("test-readonly-destroy", 40)
		require.NoError(t, err)

		err = subj.MarkReadOnly()
		assert.NoError(t, err)

		assert.True(t, subj.IsReadOnly())

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)
	})

	t.Run("should return nil data after destroying a read-only vault", func(t *testing.T) {
		// given
		subj, err := securemem.NewMemVaultData("test-nil-after-readonly-destroy", 64)
		require.NoError(t, err)

		err = subj.MarkReadOnly()
		require.NoError(t, err)

		assert.True(t, subj.IsReadOnly())

		// when
		err = subj.Destroy()
		require.NoError(t, err)

		// then
		assert.Nil(t, subj.Data())
	})

	t.Run("should preserve data after marking read-only", func(t *testing.T) {
		// given
		secret := []byte("preserve-after-readonly")
		subj, err := securemem.NewMemVaultData("test-roundtrip-readonly", len(secret))
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		copy(subj.Data(), secret)

		// when
		err = subj.MarkReadOnly()
		assert.NoError(t, err)

		// then
		assert.Equal(t, secret, subj.Data())
	})
}

func TestName(t *testing.T) {
	t.Run("should return vault name", func(t *testing.T) {
		// given
		name := "test-name"
		subj, err := securemem.NewMemVaultData(name, 32)
		require.NoError(t, err)

		t.Cleanup(func() {
			err := subj.Destroy()
			assert.NoError(t, err)
		})

		// when
		got := subj.Name()

		// then
		assert.Equal(t, name, got)
	})
}
