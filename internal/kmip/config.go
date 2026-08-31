package kmip

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/openkcm/krypton/internal/tlsconf"
)

// DefaultPort is the IANA-assigned KMIP TCP port.
const DefaultPort = 5696

var (
	ErrEmptyBindAddr = errors.New("bind_addr cannot be empty")
	ErrInvalidPort   = errors.New("port must be between 1 and 65535")
)

// Config configures the KMIP server.
type Config struct {
	BindAddr string         `yaml:"bind_addr"`
	Port     int            `yaml:"port"`
	TLS      tlsconf.Server `yaml:"tls"`
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
	return c.TLS.Validate()
}

// listenAddress returns "host:port" for use with net.Listen.
func (c *Config) listenAddress() string {
	return net.JoinHostPort(c.BindAddr, strconv.Itoa(c.Port))
}
