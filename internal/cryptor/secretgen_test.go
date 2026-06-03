package cryptor_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
)

func TestAES256SecretGen(t *testing.T) {
	// given
	ctx := t.Context()
	subj := cryptor.NewAES256SecretGenerator()

	t.Run("should generate secret successfully", func(t *testing.T) {
		// when
		res, err := subj.GenerateSecret(ctx)
		t.Cleanup(func() {
			if res != nil {
				_ = res.Secret.Destroy()
			}
		})

		// then
		assert.NoError(t, err)
		require.NotNil(t, res)
		assert.Len(t, res.Secret.SecureBytes(), 32)
		assert.Equal(t, "secretKey", res.Secret.Name())
	})

	t.Run("should generate secret randomly", func(t *testing.T) {
		foundKeys := make(map[string]struct{})

		for range 1000 {
			// when
			res, err := subj.GenerateSecret(ctx)
			t.Cleanup(func() {
				if res != nil {
					_ = res.Secret.Destroy()
				}
			})

			// then
			assert.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, "secretKey", res.Secret.Name())

			key := string(res.Secret.SecureBytes())
			assert.NotContains(t, foundKeys, key)
			foundKeys[key] = struct{}{}
		}
	})
}
