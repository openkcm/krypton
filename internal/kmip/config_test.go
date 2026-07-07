package kmip

import (
	"errors"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	valid := Config{
		BindAddr: "0.0.0.0",
		Port:     5696,
		TLS: TLSConfig{
			ServerCert: "/etc/tls/server.pem",
			ServerKey:  "/etc/tls/server-key.pem",
			ClientCA:   "/etc/tls/ca.pem",
		},
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{"valid", func(*Config) {}, nil},
		{"empty bind addr", func(c *Config) { c.BindAddr = "" }, ErrEmptyBindAddr},
		{"port too low", func(c *Config) { c.Port = 0 }, ErrInvalidPort},
		{"port too high", func(c *Config) { c.Port = 65536 }, ErrInvalidPort},
		{"empty server cert", func(c *Config) { c.TLS.ServerCert = "" }, ErrEmptyServerCert},
		{"empty server key", func(c *Config) { c.TLS.ServerKey = "" }, ErrEmptyServerKey},
		{"empty client CA", func(c *Config) { c.TLS.ClientCA = "" }, ErrEmptyClientCA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := valid
			tt.mutate(&cfg)
			err := cfg.Validate()
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfigListenAddress(t *testing.T) {
	t.Parallel()
	cfg := Config{BindAddr: "127.0.0.1", Port: 5696}
	if got := cfg.listenAddress(); got != "127.0.0.1:5696" {
		t.Fatalf("listenAddress() = %q, want %q", got, "127.0.0.1:5696")
	}
}
