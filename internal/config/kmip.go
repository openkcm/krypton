package config

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/openkcm/krypton/internal/spec"
)

// DefaultKMIPPort is the IANA-assigned KMIP TCP port.
const DefaultKMIPPort = 5696

var (
	ErrKMIPEmptyName     = errors.New("name cannot be empty")
	ErrKMIPEmptyBindAddr = errors.New("bind_addr cannot be empty")
	ErrKMIPInvalidPort   = errors.New("port must be between 1 and 65535")
	ErrKMIPInvalidConfig = errors.New("invalid kmip config")
)

// KMIPs is a slice of KMIP configs.
type KMIPs []KMIP

// KMIP configures the KMIP server.
type KMIP struct {
	Name     string    `yaml:"name"`
	BindAddr string    `yaml:"bind_addr"`
	Port     int       `yaml:"port"`
	TLS      TLSServer `yaml:"tls"`
}

// Validate checks that every KMIP entry references a topology segment whose
// end kind is the DEK kind, that no two entries share the same name, and that
// each individual KMIP config is structurally valid.
func (m KMIPs) Validate(cfg *RootConfig) error {
	dk := ""
	for _, sp := range cfg.Hierarchy.KeySpecs {
		if sp.Role == spec.KeyRoleDek {
			dk = string(sp.Kind)
			break
		}
	}

	if dk == "" && len(m) > 0 {
		return fmt.Errorf("%w: hierarchy has no DEK kind but KMIP servers are configured", ErrKMIPInvalidConfig)
	}

	das := make(map[string]struct{}, len(cfg.Topology.Segments))
	for _, seg := range cfg.Topology.Segments {
		if seg.Segment.EndKind == dk {
			das[seg.Name] = struct{}{}
		}
	}

	seen := make(map[string]struct{}, len(m))
	for _, kp := range m {
		_, ok := das[kp.Name]
		if !ok {
			return fmt.Errorf("%w: %q not a valid agent for kmip server", ErrKMIPInvalidConfig, kp.Name)
		}

		_, ok = seen[kp.Name]
		if ok {
			return fmt.Errorf("%w: duplicate kmip server for agent %q", ErrKMIPInvalidConfig, kp.Name)
		}

		seen[kp.Name] = struct{}{}

		err := kp.Validate()
		if err != nil {
			return err
		}
	}
	return nil
}

// ByName returns the first KMIP entry matching name and true, or a zero
// value and false if no entry matches.
func (m KMIPs) ByName(name string) (KMIP, bool) {
	for _, kmip := range m {
		if kmip.Name == name {
			return kmip, true
		}
	}
	return KMIP{}, false
}

// Validate checks structural correctness. It does not touch the filesystem;
// certificate/key readability is validated when the TLS config is built.
func (m *KMIP) Validate() error {
	if m.Name == "" {
		return ErrKMIPEmptyName
	}
	if m.BindAddr == "" {
		return ErrKMIPEmptyBindAddr
	}
	if m.Port < 1 || m.Port > 65535 {
		return fmt.Errorf("%w: got %d", ErrKMIPInvalidPort, m.Port)
	}
	return m.TLS.Validate()
}

// ListenAddress returns "host:port" for use with net.Listen.
func (m *KMIP) ListenAddress() string {
	return net.JoinHostPort(m.BindAddr, strconv.Itoa(m.Port))
}
