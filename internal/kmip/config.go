package kmip

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

// DefaultPort is the IANA-assigned KMIP TCP port.
const DefaultPort = 5696

var (
	ErrEmptyBindAddr   = errors.New("bind_addr cannot be empty")
	ErrInvalidPort     = errors.New("port must be between 1 and 65535")
	ErrEmptyServerCert = errors.New("tls.server_cert cannot be empty")
	ErrEmptyServerKey  = errors.New("tls.server_key cannot be empty")
	ErrEmptyClientCA   = errors.New("tls.client_ca cannot be empty")
)

// Config configures the KMIP server.
type Config struct {
	BindAddr string    `yaml:"bind_addr"`
	Port     int       `yaml:"port"`
	TLS      TLSConfig `yaml:"tls"`
}

// TLSConfig holds file paths for the server keypair and the CA bundle used
// to verify client certificates. mTLS is mandatory.
type TLSConfig struct {
	ServerCert string `yaml:"server_cert"`
	ServerKey  string `yaml:"server_key"`
	ClientCA   string `yaml:"client_ca"`
}

// Validate checks structural correctness. It does not touch the filesystem;
// certificate/key readability is validated when the TLS config is built.
func (c *Config) Validate() error {
	if c.BindAddr == "" {
		return ErrEmptyBindAddr
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("%w: got %d", ErrInvalidPort, c.Port)
	}
	if c.TLS.ServerCert == "" {
		return ErrEmptyServerCert
	}
	if c.TLS.ServerKey == "" {
		return ErrEmptyServerKey
	}
	if c.TLS.ClientCA == "" {
		return ErrEmptyClientCA
	}
	return nil
}

// listenAddress returns "host:port" for use with net.Listen.
func (c *Config) listenAddress() string {
	return net.JoinHostPort(c.BindAddr, strconv.Itoa(c.Port))
}
