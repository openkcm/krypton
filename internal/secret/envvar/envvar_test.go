package envvar_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/secret/envvar"
)

// testKey is a 32-byte AES-256 key for testing.
var testKey = []byte("01234567890123456789012345678901")

// testKeyBase64 is testKey encoded as base64 (standard encoding).
var testKeyBase64 = base64.StdEncoding.EncodeToString(testKey)

func TestConfig_ValidateSecretConfig(t *testing.T) {
	tts := []struct {
		name   string
		cfg    envvar.Config
		expErr bool
	}{
		{
			name: "should pass for non-empty name",
			cfg: envvar.Config{
				Name: "MY_SECRET",
			},
		},
		{
			name: "should fail for empty name",
			cfg: envvar.Config{
				Name: "",
			},
			expErr: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.cfg.ValidateSecretConfig()

			// then
			if tt.expErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestLoader_LoadSecret(t *testing.T) {
	t.Run("should load base64-encoded secret from env var", func(t *testing.T) {
		// given
		ctx := t.Context()
		t.Setenv("TEST_SECRET_KEY", testKeyBase64)

		loader := envvar.New(&envvar.Config{
			Name: "TEST_SECRET_KEY",
		})

		// when
		data, err := loader.LoadSecret(ctx)

		// then
		require.NoError(t, err)
		assert.Equal(t, testKey, []byte(data.SecureBytes()))
		t.Cleanup(func() { _ = data.Destroy() })
	})

	t.Run("should return error when env var is not set", func(t *testing.T) {
		// given
		ctx := t.Context()
		loader := envvar.New(&envvar.Config{
			Name: "NONEXISTENT_VAR_12345",
		})

		// when
		data, err := loader.LoadSecret(ctx)

		// then
		assert.ErrorIs(t, err, envvar.ErrEnvVarEmpty)
		assert.Nil(t, data)
	})

	t.Run("should return error for invalid base64", func(t *testing.T) {
		// given
		ctx := t.Context()
		t.Setenv("TEST_BAD_SECRET", "not-valid-base64!!!")

		loader := envvar.New(&envvar.Config{
			Name: "TEST_BAD_SECRET",
		})

		// when
		data, err := loader.LoadSecret(ctx)

		// then
		assert.ErrorIs(t, err, envvar.ErrSecureMemory)
		assert.Nil(t, data)
	})
}
