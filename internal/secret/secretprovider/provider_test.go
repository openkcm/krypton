package secretprovider_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
)

// testKey is a 32-byte AES-256 key for testing.
var testKey = []byte("01234567890123456789012345678901")

// testKeyBase64 is testKey encoded as base64 (standard encoding).
var testKeyBase64 = base64.StdEncoding.EncodeToString(testKey)

func TestSpec_Validate(t *testing.T) {
	tts := []struct {
		name   string
		spec   secretprovider.Spec
		expErr bool
	}{
		{
			name: "should fail for empty type",
			spec: secretprovider.Spec{
				Type: "",
			},
			expErr: true,
		},
		{
			name: "should pass for valid envvar spec",
			spec: secretprovider.Spec{
				Type: envvar.Type,
				Config: &envvar.Config{
					Name: "MY_KEY",
				},
			},
		},
		{
			name: "should fail when config validation fails",
			spec: secretprovider.Spec{
				Type: envvar.Type,
				Config: &envvar.Config{
					Name: "",
				},
			},
			expErr: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.spec.Validate()

			// then
			if tt.expErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestSpec_UnmarshalYAML(t *testing.T) {
	t.Run("should unmarshal valid envvar spec", func(t *testing.T) {
		// given
		input := `
type: envvar
config:
  name: MY_SECRET_KEY
`
		// when
		var spec secretprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		require.NoError(t, err)
		assert.Equal(t, envvar.Type, spec.Type)

		cfg, ok := spec.Config.(*envvar.Config)
		require.True(t, ok)
		assert.Equal(t, "MY_SECRET_KEY", cfg.Name)
	})

	t.Run("should return error for unknown type", func(t *testing.T) {
		// given
		input := `
type: unknown-type
config:
  foo: bar
`
		// when
		var spec secretprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		assert.ErrorIs(t, err, secretprovider.ErrUnknownType)
	})
}

func TestSpec_MarshalYAML(t *testing.T) {
	// given
	spec := secretprovider.Spec{
		Type: envvar.Type,
		Config: &envvar.Config{
			Name: "MY_KEY",
		},
	}

	// when
	data, err := yaml.Marshal(&spec)

	// then
	require.NoError(t, err)

	var roundTrip secretprovider.Spec
	err = yaml.Unmarshal(data, &roundTrip)
	require.NoError(t, err)

	assert.Equal(t, spec.Type, roundTrip.Type)
	cfg, ok := roundTrip.Config.(*envvar.Config)
	require.True(t, ok)
	assert.Equal(t, "MY_KEY", cfg.Name)
}

func TestGetSecret(t *testing.T) {
	t.Run("should load secret via envvar loader", func(t *testing.T) {
		// given
		ctx := t.Context()
		t.Setenv("TEST_PROVIDER_KEY", testKeyBase64)

		spec := secretprovider.Spec{
			Type: envvar.Type,
			Config: &envvar.Config{
				Name: "TEST_PROVIDER_KEY",
			},
		}

		// when
		data, err := secretprovider.GetSecret(ctx, spec)

		// then
		require.NoError(t, err)
		assert.Equal(t, testKey, []byte(data.SecureBytes()))
		t.Cleanup(func() { _ = data.Destroy() })
	})

	t.Run("should return error for unknown type", func(t *testing.T) {
		// given
		ctx := t.Context()
		spec := secretprovider.Spec{
			Type: "nonexistent",
		}

		// when
		data, err := secretprovider.GetSecret(ctx, spec)

		// then
		assert.ErrorIs(t, err, secretprovider.ErrUnknownType)
		assert.Nil(t, data)
	})
}
