package inline_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/secret/inline"
)

// testKey is a 32-byte AES-256 key for testing.
var testKey = []byte("01234567890123456789012345678901")

// testKeyBase64 is testKey encoded as base64 (standard encoding).
var testKeyBase64 = base64.StdEncoding.EncodeToString(testKey)

// shortKeyBase64 is a 16-byte key encoded as base64, i.e. an invalid AES-256 key size.
var shortKeyBase64 = base64.StdEncoding.EncodeToString([]byte("0123456789012345"))

func TestConfig_ValidateSecretConfig(t *testing.T) {
	tts := []struct {
		name   string
		cfg    inline.Config
		expErr error
	}{
		{
			name: "should pass for valid base64 32-byte secret",
			cfg: inline.Config{
				Secret: testKeyBase64,
			},
		},
		{
			name: "should fail for empty secret",
			cfg: inline.Config{
				Secret: "",
			},
			expErr: inline.ErrSecretEmpty,
		},
		{
			name: "should fail for invalid base64",
			cfg: inline.Config{
				Secret: "not-valid-base64!!!",
			},
			expErr: inline.ErrBase64Decode,
		},
		{
			name: "should fail for invalid key size",
			cfg: inline.Config{
				Secret: shortKeyBase64,
			},
			expErr: inline.ErrKeySize,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.cfg.ValidateSecretConfig()

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestLoader_LoadSecret(t *testing.T) {
	t.Run("should load base64-encoded inline secret", func(t *testing.T) {
		// given
		ctx := t.Context()
		loader := inline.New(&inline.Config{
			Secret: testKeyBase64,
		})

		// when
		data, err := loader.LoadSecret(ctx)

		// then
		require.NoError(t, err)
		assert.Equal(t, testKey, []byte(data.SecureBytes()))
		t.Cleanup(func() { _ = data.Destroy() })
	})

	t.Run("should return error for empty secret", func(t *testing.T) {
		// given
		ctx := t.Context()
		loader := inline.New(&inline.Config{
			Secret: "",
		})

		// when
		data, err := loader.LoadSecret(ctx)

		// then
		assert.ErrorIs(t, err, inline.ErrSecretEmpty)
		assert.Nil(t, data)
	})

	t.Run("should return error for invalid base64", func(t *testing.T) {
		// given
		ctx := t.Context()
		loader := inline.New(&inline.Config{
			Secret: "not-valid-base64!!!",
		})

		// when
		data, err := loader.LoadSecret(ctx)

		// then
		assert.ErrorIs(t, err, inline.ErrSecureMemory)
		assert.Nil(t, data)
	})
}
