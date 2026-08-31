package config

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/identity"
	"github.com/openkcm/krypton/internal/tlsconf"
)

const (
	// AuthTypeMTLS identifies the mTLS authentication strategy.
	AuthTypeMTLS AuthType = "mtls"
)

// AuthType is a discriminator string that selects the authentication strategy.
type AuthType string

// RootAuthConfig holds the auth section of a root instance configuration.
// It pairs an AuthType discriminator with a list of allowed identities and
// a polymorphic Config that is decoded based on the type.
type RootAuthConfig struct {
	AuthType   AuthType         `yaml:"type"`
	Identities []IdentityConfig `yaml:"identities,omitempty"`
	Config     AuthConfig       `yaml:"-"`
}

// AgentAuthConfig holds the auth section of an agent bootstrap configuration.
type AgentAuthConfig struct {
	AuthType AuthType   `yaml:"type"`
	Config   AuthConfig `yaml:"-"`
}

// MTLSConfig contains server and client TLS paths for mutual TLS authentication.
type MTLSConfig struct {
	Server tlsconf.Server `yaml:"server"`
	Client tlsconf.Client `yaml:"client"`
}

// IdentityConfig maps a human-readable name to a kryptonid:// URI.
type IdentityConfig struct {
	Name string       `yaml:"name"`
	URI  identity.URI `yaml:"uri"`
}

// AuthConfig is the interface that every authentication strategy must implement.
type AuthConfig interface {
	AuthType() AuthType
	Validate() error
}

var (
	// ErrUnknownAuthType is returned when the auth type is not recognized.
	ErrUnknownAuthType = errors.New("unknown auth type")
	// ErrNilConfig is returned when the auth config block is nil.
	ErrNilConfig = errors.New("auth config cannot be nil")
	// ErrInvalidIdentities is returned when the identities list is missing or malformed.
	ErrInvalidIdentities = errors.New("invalid identities")
)

var _ AuthConfig = (*MTLSConfig)(nil)

// Validate checks the RootAuthConfig for structural correctness, including
// the auth type, identities list, and the underlying AuthConfig.
func (m *RootAuthConfig) Validate() error {
	if m.AuthType != AuthTypeMTLS {
		return fmt.Errorf("%w: %q", ErrUnknownAuthType, m.AuthType)
	}
	if m.Config == nil {
		return ErrNilConfig
	}
	if len(m.Identities) == 0 {
		return fmt.Errorf("%w: identities cannot be empty", ErrInvalidIdentities)
	}
	for _, i := range m.Identities {
		if i.Name == "" {
			return fmt.Errorf("%w: identity name cannot be empty", ErrInvalidIdentities)
		}
		_, err := identity.Parse(i.URI)
		if err != nil {
			return fmt.Errorf("%w: invalid identity URI %q: %v", ErrInvalidIdentities, i.URI, err)
		}
	}
	return m.Config.Validate()
}

// Validate checks the AgentAuthConfig for structural correctness,
// including the auth type and the underlying AuthConfig.
func (m *AgentAuthConfig) Validate() error {
	if m.AuthType != AuthTypeMTLS {
		return fmt.Errorf("%w: %q", ErrUnknownAuthType, m.AuthType)
	}
	if m.Config == nil {
		return ErrNilConfig
	}
	return m.Config.Validate()
}

// AuthType returns AuthTypeMTLS.
func (m *MTLSConfig) AuthType() AuthType {
	return AuthTypeMTLS
}

// Validate checks that both server and client TLS paths are non-empty.
func (m *MTLSConfig) Validate() error {
	err := m.Server.Validate()
	if err != nil {
		return fmt.Errorf("server: %w", err)
	}
	err = m.Client.Validate()
	if err != nil {
		return fmt.Errorf("client: %w", err)
	}
	return nil
}

func (c *RootAuthConfig) UnmarshalYAML(node *yaml.Node) error {
	type alias RootAuthConfig
	var raw struct {
		alias `yaml:",inline"`

		Auth yaml.Node `yaml:"config"`
	}
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode auth config: %w", err)
	}

	cfg, err := newConfig(raw.AuthType)
	if err != nil {
		return err
	}

	if raw.Auth.Kind != 0 {
		if err := raw.Auth.Decode(cfg); err != nil {
			return fmt.Errorf("failed to decode auth details: %w", err)
		}
	}

	*c = RootAuthConfig(raw.alias)
	c.Config = cfg

	return nil
}

func (c *AgentAuthConfig) UnmarshalYAML(node *yaml.Node) error {
	type alias AgentAuthConfig
	var raw struct {
		alias `yaml:",inline"`

		Auth yaml.Node `yaml:"config"`
	}
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode auth config: %w", err)
	}

	cfg, err := newConfig(raw.AuthType)
	if err != nil {
		return err
	}

	if raw.Auth.Kind != 0 {
		if err := raw.Auth.Decode(cfg); err != nil {
			return fmt.Errorf("failed to decode auth details: %w", err)
		}
	}

	*c = AgentAuthConfig(raw.alias)
	c.Config = cfg

	return nil
}

// GetAuthConfig extracts the concrete *MTLSConfig from an AuthConfig interface.
// Returns ErrUnknownAuthType if the underlying type is not *MTLSConfig.
func GetAuthConfig(c AuthConfig) (*MTLSConfig, error) {
	if cfg, ok := c.(*MTLSConfig); ok {
		return cfg, nil
	}
	return nil, fmt.Errorf("%w: expected *MTLSConfig, got %T", ErrUnknownAuthType, c)
}

func newConfig(t AuthType) (AuthConfig, error) {
	switch t {
	case AuthTypeMTLS:
		return &MTLSConfig{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownAuthType, t)
	}
}
