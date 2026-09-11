package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/config"
)

func TestKMIPConfigValidate(t *testing.T) {
	t.Parallel()
	valid := config.KMIP{
		BindAddr: "0.0.0.0",
		Port:     5696,
		TLS: config.TLSServer{
			CertPath: "/etc/tls/server.pem",
			KeyPath:  "/etc/tls/server-key.pem",
			CAPath:   "/etc/tls/ca.pem",
		},
	}

	tests := []struct {
		name    string
		mutate  func(*config.KMIP)
		wantErr error
	}{
		{"valid", func(*config.KMIP) {}, nil},
		{"empty bind addr", func(c *config.KMIP) { c.BindAddr = "" }, config.ErrKMIPEmptyBindAddr},
		{"port too low", func(c *config.KMIP) { c.Port = 0 }, config.ErrKMIPInvalidPort},
		{"port too high", func(c *config.KMIP) { c.Port = 65536 }, config.ErrKMIPInvalidPort},
		{"empty server cert", func(c *config.KMIP) { c.TLS.CertPath = "" }, config.ErrInvalidTLSConfig},
		{"empty server key", func(c *config.KMIP) { c.TLS.KeyPath = "" }, config.ErrInvalidTLSConfig},
		{"empty client CA", func(c *config.KMIP) { c.TLS.CAPath = "" }, config.ErrInvalidTLSConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestConfigListenAddress(t *testing.T) {
	t.Parallel()
	cfg := config.KMIP{BindAddr: "127.0.0.1", Port: 5696}
	require.Equal(t, "127.0.0.1:5696", cfg.ListenAddress())
}
