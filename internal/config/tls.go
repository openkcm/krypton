package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSClient holds file paths for the client keypair and the server CA bundle used to verify the server (mTLS).
type TLSClient struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
	CAPath   string `yaml:"ca_path"`
}

// TLSServer holds file paths for the server keypair and the CA bundle used to verify client certificates (mTLS).
type TLSServer struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
	CAPath   string `yaml:"ca_path"`
}

var (
	// ErrCAInvalid is returned when the client CA file contains no valid certificates.
	ErrCAInvalid = errors.New("client CA file contained no valid certificates")
	// ErrInvalidTLSConfig is returned when required certificate, key, or CA paths are missing.
	ErrInvalidTLSConfig = errors.New("invalid TLS configuration: missing required certificate, key, or CA paths")
)

// BuildTLSConfig constructs a tls.Config for the client, enforcing mTLS with the provided certificates.
func (cfg *TLSClient) BuildTLSConfig() (*tls.Config, error) {
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
func (cfg *TLSClient) Validate() error {
	if cfg.CertPath == "" || cfg.KeyPath == "" || cfg.CAPath == "" {
		return ErrInvalidTLSConfig
	}
	return nil
}

// BuildTLSConfig constructs a tls.Config for the server, enforcing mTLS with the provided certificates.
func (cfg *TLSServer) BuildTLSConfig() (*tls.Config, error) {
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
func (cfg *TLSServer) Validate() error {
	if cfg.CertPath == "" || cfg.KeyPath == "" || cfg.CAPath == "" {
		return ErrInvalidTLSConfig
	}
	return nil
}

func tlsConfig(cert, key, ca string) ([]tls.Certificate, *x509.CertPool, error) {
	serverCert, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, nil, fmt.Errorf("load keypair: %w", err)
	}

	caPEM, err := os.ReadFile(ca)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA certificate: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, ErrCAInvalid
	}

	return []tls.Certificate{serverCert}, pool, nil
}
