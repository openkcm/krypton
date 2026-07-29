package sealerprovider_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/sealerprovider"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
)

func TestSpec_Validate(t *testing.T) {
	tts := []struct {
		name   string
		spec   sealerprovider.Spec
		expErr error
	}{
		{
			name: "should fail for empty name",
			spec: sealerprovider.Spec{
				Name: "",
				Type: staticsecret.TypeStaticSecret,
				Config: &staticsecret.Config{
					Secret: secretprovider.Spec{
						Type:   envvar.Type,
						Config: &envvar.Config{Name: "TEST_KEY"},
					},
				},
			},
			expErr: sealerprovider.ErrSealerNameEmpty,
		},
		{
			name: "should pass for valid staticsecret spec",
			spec: sealerprovider.Spec{
				Name: "my-sealer",
				Type: staticsecret.TypeStaticSecret,
				Config: &staticsecret.Config{
					Secret: secretprovider.Spec{
						Type:   envvar.Type,
						Config: &envvar.Config{Name: "MY_SECRET"},
					},
				},
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
	t.Run("should unmarshal staticsecret spec", func(t *testing.T) {
		// given
		input := `
name: root-sealer
type: aes256gcm-staticsecret
config:
  secret:
    type: envvar
    config:
      name: KRYPTON_ROOT_KEY
`
		// when
		var spec sealerprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		require.NoError(t, err)
		assert.Equal(t, "root-sealer", spec.Name)
		assert.Equal(t, staticsecret.TypeStaticSecret, spec.Type)
		assert.IsType(t, &staticsecret.Config{}, spec.Config)
	})

	t.Run("should return error for unknown sealer type", func(t *testing.T) {
		// given
		input := `
name: bad-sealer
type: unknown-type
config: {}
`
		// when
		var spec sealerprovider.Spec
		err := yaml.Unmarshal([]byte(input), &spec)

		// then
		assert.ErrorIs(t, err, cryptor.ErrUnknownType)
	})
}

func TestGetSealer(t *testing.T) {
	t.Run("should return error for unknown config type", func(t *testing.T) {
		// given
		ctx := t.Context()
		spec := sealerprovider.Spec{
			Name: "bad",
			Type: "unknown",
		}

		// when
		sealer, err := sealerprovider.GetSealer(ctx, spec)

		// then
		assert.ErrorIs(t, err, cryptor.ErrUnknownType)
		assert.Nil(t, sealer)
	})
}
