package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

var (
	// ErrCAInvalid is returned when the client CA file contains no valid certificates.
	ErrCAInvalid = errors.New("client CA file contained no valid certificates")
	// ErrInvalidTLSConfig is returned when required certificate, key, or CA paths are missing.
	ErrInvalidTLSConfig = errors.New("invalid TLS configuration: missing required certificate, key, or CA paths")
)

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
