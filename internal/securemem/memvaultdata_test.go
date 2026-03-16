package securemem_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/securemem"
)

func TestNewWithSize(t *testing.T) {
	t.Run("should create vault with specified size", func(t *testing.T) {
		// given when
		subj, err := securemem.NewMemVaultData("test-region", 64)
		assert.NoError(t, err)

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
}

func TestDestroy(t *testing.T) {
	t.Run("should securely destroy vault data", func(t *testing.T) {
		// given
		subj, err := securemem.NewMemVaultData("test-destroy", 128)
		assert.NoError(t, err)

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)
		assert.Nil(t, subj.Data())
	})

	t.Run("should be idempotent", func(t *testing.T) {
		// given
		subj, err := securemem.NewMemVaultData("test-idempotent", 64)
		assert.NoError(t, err)

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
		assert.NoError(t, err)

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
		assert.NoError(t, err)

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
		assert.NoError(t, err)

		err = subj.MarkReadOnly()
		assert.NoError(t, err)

		assert.True(t, subj.IsReadOnly())

		// when
		err = subj.Destroy()

		// then
		assert.NoError(t, err)
	})
}
