package spec_test

import (
	"testing"

	"github.com/openkcm/krypton/internal/spec"
	"github.com/stretchr/testify/assert"
)

func TestOpenBaoVaultConfig(t *testing.T) {
	tts := []struct {
		name   string
		cfg    *spec.OpenBAOConfig
		expErr error
	}{
		{
			name: "empty cluster address",
			cfg: &spec.OpenBAOConfig{
				ClusterAddress: "",
			},
			expErr: spec.ErrVaultConfigInvalid,
		},
		{
			name: "valid config",
			cfg: &spec.OpenBAOConfig{
				ClusterAddress: "test-cluster-address",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.cfg.IsValidVaultConfig()

			// then
			assert.ErrorIs(t, err, tt.expErr)
		})
	}
}

func TestInMemoryConfig(t *testing.T) {
	tts := []struct {
		name   string
		cfg    *spec.InMemoryConfig
		expErr error
	}{
		{
			name: "empty prefix",
			cfg: &spec.InMemoryConfig{
				Prefix: "",
			},
			expErr: spec.ErrVaultConfigInvalid,
		},
		{
			name: "valid config",
			cfg: &spec.InMemoryConfig{
				Prefix: "test-prefix",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			err := tt.cfg.IsValidVaultConfig()

			// then
			assert.ErrorIs(t, err, tt.expErr)
		})
	}
}
