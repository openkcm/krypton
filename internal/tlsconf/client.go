package tlsconf

import "crypto/tls"

// Client holds file paths for the client keypair and the server CA bundle used to verify the server (mTLS).
type Client struct {
	Cert     string `yaml:"client_cert"`
	Key      string `yaml:"client_key"`
	ServerCA string `yaml:"server_ca"`
}

// BuildTLSConfig constructs a tls.Config for the client, enforcing mTLS with the provided certificates.
func (cfg *Client) BuildTLSConfig() (*tls.Config, error) {
	certs, pool, err := tlsConfig(cfg.Cert, cfg.Key, cfg.ServerCA)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: certs,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
