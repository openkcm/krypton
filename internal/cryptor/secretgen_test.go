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

	t.Run("should return error", func(t *testing.T) {
		// given
		tts := []struct {
			name    string
			request cryptor.GenerateSecretRequest
		}{
			{
				name: "if algorithm is not supported",
				request: cryptor.GenerateSecretRequest{
					Algorithm: "unknown",
					Name:      "name",
				},
			},
			{
				name: "if name is empty",
				request: cryptor.GenerateSecretRequest{
					Algorithm: cryptor.KeyAlgorithmAES256,
					Name:      "",
				},
			},
		}

		for _, tt := range tts {
			t.Run(tt.name, func(t *testing.T) {
				// when
				res, err := subj.GenerateSecret(ctx, tt.request)

				// then
				assert.Error(t, err)
				assert.ErrorIs(t, err, cryptor.ErrSecretGenRequest)
				assert.Nil(t, res)
			})
		}
	})

	t.Run("should generate secret successfully", func(t *testing.T) {
		// when
		res, err := subj.GenerateSecret(ctx, cryptor.GenerateSecretRequest{
			Name:      "secret-key",
			Algorithm: cryptor.KeyAlgorithmAES256,
		})
		t.Cleanup(func() {
			if res != nil {
				_ = res.Secret.Destroy()
			}
		})

		// then
		assert.NoError(t, err)
		require.NotNil(t, res)
		assert.Len(t, res.Secret.SecureBytes(), 32)
		assert.Equal(t, "secret-key", res.Secret.Name())
	})

	t.Run("should generate secret randomly", func(t *testing.T) {
		foundKeys := make(map[string]struct{})

		for range 1000 {
			// when
			res, err := subj.GenerateSecret(ctx, cryptor.GenerateSecretRequest{
				Name:      "secret",
				Algorithm: cryptor.KeyAlgorithmAES256,
			})
			t.Cleanup(func() {
				if res != nil {
					_ = res.Secret.Destroy()
				}
			})

			// then
			assert.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, "secret", res.Secret.Name())

			key := string(res.Secret.SecureBytes())
			assert.NotContains(t, foundKeys, key)
			foundKeys[key] = struct{}{}
		}
	})
}
