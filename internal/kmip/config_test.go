package kmip_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/kmip"
	"github.com/openkcm/krypton/internal/tlsconf"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	valid := kmip.Config{
		BindAddr: "0.0.0.0",
		Port:     5696,
		TLS: tlsconf.Server{
			CertPath: "/etc/tls/server.pem",
			KeyPath:  "/etc/tls/server-key.pem",
			CAPath:   "/etc/tls/ca.pem",
		},
	}

	tests := []struct {
		name    string
		mutate  func(*kmip.Config)
		wantErr error
	}{
		{"valid", func(*kmip.Config) {}, nil},
		{"empty bind addr", func(c *kmip.Config) { c.BindAddr = "" }, kmip.ErrEmptyBindAddr},
		{"port too low", func(c *kmip.Config) { c.Port = 0 }, kmip.ErrInvalidPort},
		{"port too high", func(c *kmip.Config) { c.Port = 65536 }, kmip.ErrInvalidPort},
		{"empty server cert", func(c *kmip.Config) { c.TLS.CertPath = "" }, tlsconf.ErrInvalidTLSConfig},
		{"empty server key", func(c *kmip.Config) { c.TLS.KeyPath = "" }, tlsconf.ErrInvalidTLSConfig},
		{"empty client CA", func(c *kmip.Config) { c.TLS.CAPath = "" }, tlsconf.ErrInvalidTLSConfig},
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
	cfg := kmip.Config{BindAddr: "127.0.0.1", Port: 5696}
	require.Equal(t, "127.0.0.1:5696", kmip.ListenAddress(&cfg))
}
