package tlsconf

import (
	"crypto/tls"
)

// Server holds file paths for the server keypair and the CA bundle used to verify client certificates (mTLS).
type Server struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
	CAPath   string `yaml:"ca_path"`
}

// BuildTLSConfig constructs a tls.Config for the server, enforcing mTLS with the provided certificates.
func (cfg *Server) BuildTLSConfig() (*tls.Config, error) {
	certs, pool, err := tlsConfig(cfg.CertPath, cfg.KeyPath, cfg.CAPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: certs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Validate checks that all required paths are provided for the server configuration.
func (cfg *Server) Validate() error {
	if cfg.CertPath == "" || cfg.KeyPath == "" || cfg.CAPath == "" {
		return ErrInvalidTLSConfig
	}
	return nil
}
