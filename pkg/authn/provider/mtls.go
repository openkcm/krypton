package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/openkcm/krypton/internal/tlsconf"
	"github.com/openkcm/krypton/pkg/authn"
)

// MTLS is an authentication provider that verifies client identity using mutual TLS certificates.
type MTLS struct{}

var _ authn.Provider = &MTLS{}

// MTLSCredentialsValue holds the file paths to the client certificate, private key, and CA certificate.
type MTLSCredentialsValue struct {
	PublicCertPath string `json:"public_cert_path"`
	PrivateKeyPath string `json:"private_key_path"`
	CaCertPath     string `json:"ca_cert_path"`
}

var errCertAppendFailed = errors.New("failed to append CA certificate")

func (m *MTLS) Validate(_ context.Context, t *authn.Token) (authn.ValidationResult, error) {
	if t.Type != authn.MTLS {
		return authn.ValidationResult{Status: authn.InvalidStatus}, nil
	}

	v := MTLSCredentialsValue{}
	err := json.Unmarshal(t.Value, &v)
	if err != nil {
		return authn.ValidationResult{Status: authn.InvalidStatus}, nil
	}

	err = v.verifyCertChain()
	if err != nil {
		return authn.ValidationResult{Status: authn.InvalidStatus}, nil
	}

	return authn.ValidationResult{Status: authn.ValidStatus}, nil
}

func (m *MTLS) Verify(_ context.Context, creds *authn.Credentials) (*authn.Token, error) {
	if creds == nil {
		return nil, fmt.Errorf("credentials cannot be nil: %w", authn.ErrInvalidCredentials)
	}

	if creds.Type != authn.MTLS {
		return nil, fmt.Errorf("invalid credentials type: %s: %w", creds.Type, authn.ErrInvalidCredentials)
	}

	v := MTLSCredentialsValue{}
	err := json.Unmarshal(creds.Value, &v)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials value: %w", errors.Join(err, authn.ErrInvalidCredentials))
	}

	err = v.verifyCertChain()
	if err != nil {
		return nil, fmt.Errorf("failed to verify cert/key pair: %w", errors.Join(err, authn.ErrInvalidCredentials))
	}

	return &authn.Token{
		Type:  authn.MTLS,
		Value: creds.Value,
	}, nil
}

func NewMTLSCredentialsValue(b []byte) (*MTLSCredentialsValue, error) {
	v := MTLSCredentialsValue{}
	err := json.Unmarshal(b, &v)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credentials value: %w", err)
	}

	return &v, nil
}

func (v *MTLSCredentialsValue) TLSConfig() (*tls.Config, error) {
	return (&tlsconf.Client{
		Cert:     v.PublicCertPath,
		Key:      v.PrivateKeyPath,
		ServerCA: v.CaCertPath,
	}).BuildTLSConfig()
}

func (v *MTLSCredentialsValue) verifyCertChain() error {
	cert, err := tls.LoadX509KeyPair(v.PublicCertPath, v.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load cert/key: %w", err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	caCert, err := os.ReadFile(v.CaCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return errCertAppendFailed
	}

	opts := x509.VerifyOptions{
		Roots:     certPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if len(cert.Certificate) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, der := range cert.Certificate[1:] {
			intermediate, err := x509.ParseCertificate(der)
			if err != nil {
				return fmt.Errorf("failed to parse intermediate certificate: %w", err)
			}
			opts.Intermediates.AddCert(intermediate)
		}
	}

	_, err = x509Cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}
