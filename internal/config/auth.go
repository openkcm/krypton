package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

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

// IdentityConfigs is a list of named identity configurations.
type IdentityConfigs []IdentityConfig

// RootAuthConfig holds the auth section of a root instance configuration.
// It pairs an AuthType discriminator with a list of allowed identities and
// a polymorphic Config that is decoded based on the type.
type RootAuthConfig struct {
	AuthType        AuthType        `yaml:"type"`
	IdentityConfigs IdentityConfigs `yaml:"identity"`
	Config          AuthConfig      `yaml:"-"`
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
func (c *RootAuthConfig) Validate() error {
	if c.AuthType != AuthTypeMTLS {
		return fmt.Errorf("%w: %q", ErrUnknownAuthType, c.AuthType)
	}

	if len(c.IdentityConfigs) == 0 {
		return fmt.Errorf("%w: identities cannot be empty", ErrInvalidIdentities)
	}
	for _, i := range c.IdentityConfigs {
		if strings.TrimSpace(i.Name) == "" {
			return fmt.Errorf("%w: identity name cannot be empty", ErrInvalidIdentities)
		}
		_, err := identity.Parse(i.URI)
		if err != nil {
			return fmt.Errorf("%w: invalid identity URI %q", errors.Join(ErrInvalidIdentities, err), i.URI)
		}
	}

	if c.Config == nil {
		return ErrNilConfig
	}
	return c.Config.Validate()
}

// Validate checks the AgentAuthConfig for structural correctness,
// including the auth type and the underlying AuthConfig.
func (c *AgentAuthConfig) Validate() error {
	if c.AuthType != AuthTypeMTLS {
		return fmt.Errorf("%w: %q", ErrUnknownAuthType, c.AuthType)
	}

	if c.Config == nil {
		return ErrNilConfig
	}
	return c.Config.Validate()
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

// GetAuthConfig extracts the concrete *MTLSConfig from an AuthConfig interface.
// Returns ErrUnknownAuthType if the underlying type is not *MTLSConfig.
func GetAuthConfig(c AuthConfig) (*MTLSConfig, error) {
	if cfg, ok := c.(*MTLSConfig); ok {
		return cfg, nil
	}
	return nil, fmt.Errorf("%w: expected *MTLSConfig, got %T", ErrUnknownAuthType, c)
}

// URIs returns a slice of the URI strings from the Identities list.
func (i IdentityConfigs) URIs() []string {
	res := make([]string, 0, len(i))
	for _, id := range i {
		res = append(res, string(id.URI))
	}
	return res
}

// ValidateAuthIdentities checks that every root and topology segment name
// has a corresponding identity entry, with no duplicates.
func (i IdentityConfigs) ValidateAuthIdentities(cfg *RootConfig) error {
	expected := make(map[string]struct{}, len(cfg.Topology.Segments)+1)
	expected[cfg.Name] = struct{}{}
	for _, seg := range cfg.Topology.Segments {
		expected[seg.Name] = struct{}{}
	}

	seen := make(map[string]struct{}, len(i))
	for _, id := range i {
		if _, ok := seen[id.Name]; ok {
			return fmt.Errorf("%w: duplicate identity name %q", ErrInvalidIdentities, id.Name)
		}
		seen[id.Name] = struct{}{}
		delete(expected, id.Name)
	}

	if len(expected) > 0 {
		return fmt.Errorf("%w: missing identities for segments: %v", ErrInvalidIdentities, slices.Collect(maps.Keys(expected)))
	}

	return nil
}

func newConfig(t AuthType) (AuthConfig, error) {
	switch t {
	case AuthTypeMTLS:
		return &MTLSConfig{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownAuthType, t)
	}
}
