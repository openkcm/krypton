package securemem_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/openkcm/krypton/internal/securemem"
)

func TestNewVault(t *testing.T) {
	// given
	// when
	subj := securemem.NewMemVault()

	// then
	assert.NotNil(t, subj)
}

func TestGet(t *testing.T) {
	t.Run("should return data from vault", func(t *testing.T) {
		// given
		name := "test"
		data := []byte("secret")
		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		b, err := subj.Reserve(name, len(data))
		assert.NoError(t, err)
		copy(b, data)

		// when
		actResult, ok := subj.Get(name)

		// then
		assert.True(t, ok)
		assert.Equal(t, data, actResult)
	})

	t.Run("should return false when data does not exist in vault", func(t *testing.T) {
		// given
		name := "non-existing"
		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		// when
		actResult, ok := subj.Get(name)

		// then
		assert.False(t, ok)
		assert.Nil(t, actResult)
	})
}

func TestReserve(t *testing.T) {
	t.Run("should reserve a buffer in the vault", func(t *testing.T) {
		// given
		keys := []string{"test1", "test2", "test3"}
		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		// when
		for _, name := range keys {
			b, err := subj.Reserve(name, len(name))

			// then
			assert.NoError(t, err)
			copy(b, name)
		}

		for _, name := range keys {
			// then
			actResult, ok := subj.Get(name)
			assert.True(t, ok)
			assert.Equal(t, name, string(actResult))
		}
	})

	t.Run("should return error when reserve", func(t *testing.T) {
		tts := []struct {
			name string
			size int
		}{
			{name: "size is 0", size: 0},
			{name: "size is negative", size: -1},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// given
				name := "foo"
				subj := securemem.NewMemVault()

				t.Cleanup(func() {
					err := subj.DestroyAll()
					assert.NoError(t, err)
				})

				// when
				actBytes, err := subj.Reserve(name, tt.size)

				// then
				assert.ErrorIs(t, err, securemem.ErrInvalidSize)
				assert.Nil(t, actBytes)
			})
		}
	})

	t.Run("should return an error if we reserve data with same name", func(t *testing.T) {
		// given
		name := "test"
		data := []byte("secret1")
		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		// when
		actBytes, err := subj.Reserve(name, len(data))

		// then
		assert.NoError(t, err)
		assert.Len(t, actBytes, len(data))

		// when
		actBytes, err = subj.Reserve(name, len(data))

		// then
		assert.Error(t, err)
		assert.ErrorIs(t, err, securemem.ErrVaultDataAlreadyExists)
		assert.Nil(t, actBytes)
	})

	t.Run("should not change the original data after copying data into vault", func(t *testing.T) {
		// given
		name := "test"
		data := []byte("secret")
		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		// when
		b, err := subj.Reserve(name, len(data))
		copy(b, data)

		// then
		assert.NoError(t, err)

		actResult, ok := subj.Get(name)
		assert.True(t, ok)
		assert.Equal(t, data, actResult)

		data[0] = 'S'

		actResult, ok = subj.Get(name)
		assert.True(t, ok)
		assert.Equal(t, []byte("secret"), actResult)
	})
}

func TestVaultDestroy(t *testing.T) {
	t.Run("destroy", func(t *testing.T) {
		t.Run("should destroy a specific data in vault", func(t *testing.T) {
			// given
			name1 := "test1"
			name2 := "test2"
			name3 := "test3"
			data1 := []byte("secret1")
			data2 := []byte("secret2")
			data3 := []byte("secret3")

			subj := securemem.NewMemVault()

			t.Cleanup(func() {
				err := subj.DestroyAll()
				assert.NoError(t, err)
			})

			b1, err := subj.Reserve(name1, len(data1))
			assert.NoError(t, err)
			copy(b1, data1)

			b2, err := subj.Reserve(name2, len(data2))
			assert.NoError(t, err)
			copy(b2, data2)

			_, err = subj.Reserve(name3, len(data3))
			assert.NoError(t, err)

			// when
			err = subj.Destroy(name1)
			assert.NoError(t, err)

			err = subj.Destroy(name3)
			assert.NoError(t, err)

			// then
			actBytes, ok := subj.Get(name1)
			assert.False(t, ok)
			assert.Nil(t, actBytes)

			actBytes, ok = subj.Get(name2)
			assert.True(t, ok)
			assert.Equal(t, data2, actBytes)

			actBytes, ok = subj.Get(name3)
			assert.False(t, ok)
			assert.Nil(t, actBytes)
		})

		t.Run("should be idempotent when destroying data", func(t *testing.T) {
			// given
			name := "test"
			size := 10

			subj := securemem.NewMemVault()

			t.Cleanup(func() {
				err := subj.DestroyAll()
				assert.NoError(t, err)
			})

			b, err := subj.Reserve(name, size)
			assert.NoError(t, err)
			assert.Len(t, b, size)

			// when
			err = subj.Destroy(name)
			assert.NoError(t, err)

			err = subj.Destroy(name)
			assert.NoError(t, err)

			// then
			actBytes, ok := subj.Get(name)
			assert.False(t, ok)
			assert.Nil(t, actBytes)
		})

		t.Run("should not return an error when destroying non-existing data", func(t *testing.T) {
			// given
			name := "test"
			subj := securemem.NewMemVault()

			t.Cleanup(func() {
				err := subj.DestroyAll()
				assert.NoError(t, err)
			})

			// when
			err := subj.Destroy(name)

			// then
			assert.NoError(t, err)
		})

		t.Run("should be able to reuse the name after destroying data", func(t *testing.T) {
			// given
			name := "test"
			data1 := []byte("secret1")
			data2 := []byte("secret2")
			subj := securemem.NewMemVault()

			t.Cleanup(func() {
				err := subj.DestroyAll()
				assert.NoError(t, err)
			})

			b, err := subj.Reserve(name, len(data1))
			assert.NoError(t, err)
			assert.Len(t, b, len(data1))
			copy(b, data1)

			// when
			err = subj.Destroy(name)
			assert.NoError(t, err)

			b, err = subj.Reserve(name, len(data2))
			assert.NoError(t, err)
			copy(b, data2)

			// then
			actBytes, ok := subj.Get(name)
			assert.True(t, ok)
			assert.Equal(t, data2, actBytes)
		})
	})

	t.Run("destroy all", func(t *testing.T) {
		t.Run("should destroy all data in vault", func(t *testing.T) {
			// given
			name1 := "test1"
			name2 := "test2"
			name3 := "test3"

			subj := securemem.NewMemVault()

			t.Cleanup(func() {
				err := subj.DestroyAll()
				assert.NoError(t, err)
			})

			_, err := subj.Reserve(name1, 1)
			assert.NoError(t, err)

			_, err = subj.Reserve(name2, 2)
			assert.NoError(t, err)

			_, err = subj.Reserve(name3, 3)
			assert.NoError(t, err)

			// when
			err = subj.DestroyAll()
			assert.NoError(t, err)

			// then
			actBytes, ok := subj.Get(name1)
			assert.False(t, ok)
			assert.Nil(t, actBytes)

			actBytes, ok = subj.Get(name2)
			assert.False(t, ok)
			assert.Nil(t, actBytes)

			actBytes, ok = subj.Get(name3)
			assert.False(t, ok)
			assert.Nil(t, actBytes)
		})

		t.Run("should be idempotent when destroying all data", func(t *testing.T) {
			// given
			name := "test"

			subj := securemem.NewMemVault()

			t.Cleanup(func() {
				err := subj.DestroyAll()
				assert.NoError(t, err)
			})

			_, err := subj.Reserve(name, 10)
			assert.NoError(t, err)

			// when
			err = subj.DestroyAll()
			assert.NoError(t, err)

			err = subj.DestroyAll()
			assert.NoError(t, err)

			// then
			actBytes, ok := subj.Get(name)
			assert.False(t, ok)
			assert.Nil(t, actBytes)
		})

		t.Run("should not return an error when vault is empty", func(t *testing.T) {
			// given
			subj := securemem.NewMemVault()

			// when
			err := subj.DestroyAll()

			// then
			assert.NoError(t, err)
		})

		t.Run("should be able to reuse the names after destroying all data", func(t *testing.T) {
			// given
			name1 := "test1"
			name2 := "test2"
			data1 := []byte("secret1")
			data2 := []byte("secret2")

			subj := securemem.NewMemVault()

			t.Cleanup(func() {
				err := subj.DestroyAll()
				assert.NoError(t, err)
			})

			b, err := subj.Reserve(name1, len(data1))
			assert.NoError(t, err)
			copy(b, data1)

			b, err = subj.Reserve(name2, len(data2))
			assert.NoError(t, err)
			copy(b, data2)

			// when
			err = subj.DestroyAll()
			assert.NoError(t, err)

			b, err = subj.Reserve(name1, len(data1))
			assert.NoError(t, err)
			copy(b, data1)

			b, err = subj.Reserve(name2, len(data2))
			assert.NoError(t, err)
			copy(b, data2)

			// then
			actBytes, ok := subj.Get(name1)
			assert.True(t, ok)
			assert.Equal(t, data1, actBytes)

			actBytes, ok = subj.Get(name2)
			assert.True(t, ok)
			assert.Equal(t, data2, actBytes)
		})
	})
}

func TestVaultMarkReadOnly(t *testing.T) {
	t.Run("should mark all data in vault as read-only", func(t *testing.T) {
		// given
		name1 := "test1"
		name2 := "test2"
		data1 := []byte("secret1")
		data2 := []byte("secret2")

		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		b, err := subj.Reserve(name1, len(data1))
		assert.NoError(t, err)
		copy(b, data1)

		b, err = subj.Reserve(name2, len(data2))
		assert.NoError(t, err)
		copy(b, data2)

		// when
		err = subj.MarkAllReadOnly()
		assert.NoError(t, err)

		// then
		actBytes, ok := subj.Get(name1)
		assert.True(t, ok)
		assert.Equal(t, data1, actBytes)

		actBytes, ok = subj.Get(name2)
		assert.True(t, ok)
		assert.Equal(t, data2, actBytes)
	})

	t.Run("should be idempotent when marking all data as read-only", func(t *testing.T) {
		// given
		name := "test"
		data := []byte("secret")

		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		b, err := subj.Reserve(name, len(data))
		assert.NoError(t, err)
		copy(b, data)

		// when
		err = subj.MarkAllReadOnly()
		assert.NoError(t, err)

		err = subj.MarkAllReadOnly()
		assert.NoError(t, err)

		// then
		actBytes, ok := subj.Get(name)
		assert.True(t, ok)
		assert.Equal(t, data, actBytes)
	})

	t.Run("should not return an error when vault is empty", func(t *testing.T) {
		// given
		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		// when
		err := subj.MarkAllReadOnly()

		// then
		assert.NoError(t, err)
	})

	t.Run("should destroy after marking all data as read-only", func(t *testing.T) {
		// given
		name := "test"
		data := []byte("secret")

		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		b, err := subj.Reserve(name, len(data))
		assert.NoError(t, err)
		copy(b, data)

		// when
		err = subj.MarkAllReadOnly()
		assert.NoError(t, err)

		err = subj.Destroy(name)
		assert.NoError(t, err)

		// then
		actBytes, ok := subj.Get(name)
		assert.False(t, ok)
		assert.Nil(t, actBytes)
	})

	t.Run("should not able to reserve new data after marking all data as read-only", func(t *testing.T) {
		// given
		name := "test"
		data := []byte("secret")

		subj := securemem.NewMemVault()

		t.Cleanup(func() {
			err := subj.DestroyAll()
			assert.NoError(t, err)
		})

		b, err := subj.Reserve(name, len(data))
		assert.NoError(t, err)
		copy(b, data)

		// when
		err = subj.MarkAllReadOnly()
		assert.NoError(t, err)

		res, err := subj.Reserve("new-data", 10)

		// then
		assert.ErrorIs(t, err, securemem.ErrVaultReadOnly)
		assert.Nil(t, res)

		aByte, ok := subj.Get(name)
		assert.True(t, ok)
		assert.Equal(t, data, aByte)
	})
}
