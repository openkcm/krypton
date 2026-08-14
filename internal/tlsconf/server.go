package tlsconf

import (
	"crypto/tls"
)

// Server holds file paths for the server keypair and the CA bundle used to verify client certificates (mTLS).
type Server struct {
	Cert     string `yaml:"server_cert"`
	Key      string `yaml:"server_key"`
	ClientCA string `yaml:"client_ca"`
}

// BuildTLSConfig constructs a tls.Config for the server, enforcing mTLS with the provided certificates.
func (cfg *Server) BuildTLSConfig() (*tls.Config, error) {
	certs, pool, err := tlsConfig(cfg.Cert, cfg.Key, cfg.ClientCA)
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
