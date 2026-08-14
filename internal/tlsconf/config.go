package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ErrCAInvalid is returned when the client CA file contains no valid certificates.
var ErrCAInvalid = errors.New("client CA file contained no valid certificates")

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
