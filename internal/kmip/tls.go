package kmip

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// ErrClientCAInvalid indicates the client CA file did not contain any
// parseable PEM certificates.
var ErrClientCAInvalid = errors.New("client CA file contained no valid certificates")

// buildTLSConfig loads the server keypair and the client CA bundle from disk
// and returns a *tls.Config that requires and verifies client certificates.
func buildTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCert, cfg.ServerKey)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.ClientCA)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, ErrClientCAInvalid
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
