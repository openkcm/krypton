package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

// DefaultKMIPPort is the IANA-assigned KMIP TCP port.
const DefaultKMIPPort = 5696

var (
	ErrKMIPEmptyBindAddr = errors.New("bind_addr cannot be empty")
	ErrKMIPInvalidPort   = errors.New("port must be between 1 and 65535")
)

// KMIP configures the KMIP server.
type KMIP struct {
	BindAddr string    `yaml:"bind_addr"`
	Port     int       `yaml:"port"`
	TLS      TLSServer `yaml:"tls"`
}

// Validate checks structural correctness. It does not touch the filesystem;
// certificate/key readability is validated when the TLS config is built.
func (c *KMIP) Validate() error {
	if c.BindAddr == "" {
		return ErrKMIPEmptyBindAddr
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("%w: got %d", ErrKMIPInvalidPort, c.Port)
	}
	return c.TLS.Validate()
}

// ListenAddress returns "host:port" for use with net.Listen.
func (c *KMIP) ListenAddress() string {
	return net.JoinHostPort(c.BindAddr, strconv.Itoa(c.Port))
}
