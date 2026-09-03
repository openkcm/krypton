package tlsconf

import (
	"crypto/tls"
)

// Client holds file paths for the client keypair and the server CA bundle used to verify the server (mTLS).
type Client struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
	CAPath   string `yaml:"ca_path"`
}

// BuildTLSConfig constructs a tls.Config for the client, enforcing mTLS with the provided certificates.
func (cfg *Client) BuildTLSConfig() (*tls.Config, error) {
	certs, pool, err := tlsConfig(cfg.CertPath, cfg.KeyPath, cfg.CAPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: certs,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Validate checks that all required paths are provided for the client configuration.
func (cfg *Client) Validate() error {
	if cfg.CertPath == "" || cfg.KeyPath == "" || cfg.CAPath == "" {
		return ErrInvalidTLSConfig
	}
	return nil
}
