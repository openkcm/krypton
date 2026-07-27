package cryptorprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/cryptorprovider"
)

func TestSpec_Validate(t *testing.T) {
	tts := []struct {
		name   string
		spec   cryptorprovider.Spec
		expErr error
	}{
		{
			name: "should fail for empty name",
			spec: cryptorprovider.Spec{
				Name:   "",
				Type:   aes256gcm.TypeAES256GCM,
				Config: &aes256gcm.Config{},
			},
			expErr: cryptorprovider.ErrCryptorNameEmpty,
		},
		{
			name: "should pass for valid aes256gcm spec",
			spec: cryptorprovider.Spec{
				Name:   "my-cryptor",
				Type:   aes256gcm.TypeAES256GCM,
				Config: &aes256gcm.Config{},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.spec.Validate()

			// then
			if tt.expErr != nil {
				assert.ErrorIs(t, err, tt.expErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestSpec_UnmarshalYAML(t *testing.T) {
	t.Run("should unmarshal aes256gcm spec", func(t *testing.T) {
		// given
		input := `
name: root-cryptor
type: aes256gcm
config: {}
`
		// when
		var spec cryptorprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		require.NoError(t, err)
		assert.Equal(t, "root-cryptor", spec.Name)
		assert.Equal(t, aes256gcm.TypeAES256GCM, spec.Type)
		assert.IsType(t, &aes256gcm.Config{}, spec.Config)
	})

	t.Run("should return error for unknown cryptor type", func(t *testing.T) {
		// given
		input := `
name: bad-cryptor
type: unknown-type
config: {}
`
		// when
		var spec cryptorprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		assert.ErrorIs(t, err, cryptor.ErrUnknownType)
	})
}

func TestGetBundle(t *testing.T) {
	t.Run("should return bundle with cryptor and secret generator for aes256gcm", func(t *testing.T) {
		// given
		ctx := t.Context()
		spec := cryptorprovider.Spec{
			Name:   "test-cryptor",
			Type:   aes256gcm.TypeAES256GCM,
			Config: &aes256gcm.Config{},
		}

		// when
		bundle, err := cryptorprovider.GetBundle(ctx, spec)

		// then
		require.NoError(t, err)
		assert.NotNil(t, bundle.Cryptor)
		assert.NotNil(t, bundle.SecretGenerator)

		info := bundle.Cryptor.Info()
		assert.Equal(t, "test-cryptor", info.Name)
		assert.Equal(t, aes256gcm.TypeAES256GCM, info.Type)
	})

	t.Run("should return error for unknown config type", func(t *testing.T) {
		// given
		ctx := t.Context()
		spec := cryptorprovider.Spec{
			Name: "bad",
			Type: "unknown",
		}

		// when
		bundle, err := cryptorprovider.GetBundle(ctx, spec)

		// then
		assert.ErrorIs(t, err, cryptor.ErrUnknownType)
		assert.Zero(t, bundle)
	})
}
