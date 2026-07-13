package vaultprovider

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	openbao "github.com/openbao/openbao/api/v2"

	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/openbaovault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
)

var ErrVaultNameEmpty = errors.New("vault name is empty")

// Spec describes which vault implementation to use and how to configure it.
type Spec struct {
	Name string     `yaml:"name"`
	Type vault.Type `yaml:"type"`
	// Config is marshaled/unmarshaled via custom MarshalYAML/UnmarshalYAML, not by the default YAML codec.
	Config vault.Config `yaml:"-"`
}

var (
	_ yaml.Unmarshaler = (*Spec)(nil)
	_ yaml.Marshaler   = (*Spec)(nil)
)

// MarshalYAML implements [yaml.Marshaler].
func (s *Spec) MarshalYAML() (any, error) {
	type alias Spec
	return struct {
		alias `yaml:",inline"`

		Config vault.Config `yaml:"config,omitempty"`
	}{
		alias:  alias(*s),
		Config: s.Config,
	}, nil
}

// UnmarshalYAML implements [yaml.Unmarshaler].
func (s *Spec) UnmarshalYAML(node *yaml.Node) error {
	type alias Spec
	var raw struct {
		alias `yaml:",inline"`

		Config yaml.Node `yaml:"config"`
	}
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode vault spec: %w", err)
	}

	cfg, err := newConfig(raw.Type)
	if err != nil {
		return err
	}

	if raw.Config.Kind != 0 {
		if err := raw.Config.Decode(cfg); err != nil {
			return fmt.Errorf("failed to decode vault config: %w", err)
		}
	}

	*s = Spec(raw.alias)
	s.Config = cfg
	return nil
}

// Validate checks the Spec for structural correctness.
func (s *Spec) Validate() error {
	if s.Name == "" {
		return ErrVaultNameEmpty
	}
	if _, err := newConfig(s.Type); err != nil {
		return err
	}
	if s.Config != nil {
		if err := s.Config.ValidateVaultConfig(); err != nil {
			return err
		}
	}
	return nil
}

// GetVault constructs a ready-to-use vault.Vault from the given Spec.
func GetVault(ctx context.Context, spec Spec) (vault.Vault, error) {
	switch spec.Type {
	case sqlitevault.TypeUnsafeMemory:
		return sqlitevault.NewUnsafe(ctx, spec.Name, sqlitevault.MemorySource)
	case sqlitevault.TypeUnsafe:
		cfg, ok := spec.Config.(*sqlitevault.FileConfig)
		if !ok {
			return nil, fmt.Errorf("expected *sqlitevault.FileConfig for type %q, got %T", spec.Type, spec.Config)
		}
		return sqlitevault.NewUnsafe(ctx, spec.Name, sqlitevault.FileSource(cfg.Path))
	case openbaovault.TypeOpenBao:
		cfg, ok := spec.Config.(*openbaovault.Config)
		if !ok {
			return nil, fmt.Errorf("expected *openbaovault.Config for type %q, got %T", spec.Type, spec.Config)
		}
		return openbaovault.New(spec.Name, func(c *openbao.Client) error {
			return c.SetAddress(cfg.Address)
		})
	default:
		return nil, fmt.Errorf("%w: %q", vault.ErrUnknownType, spec.Type)
	}
}

// newConfig is a factory that creates the correct Config struct by vault type.
func newConfig(t vault.Type) (vault.Config, error) {
	switch t {
	case sqlitevault.TypeUnsafeMemory:
		return &sqlitevault.InMemoryConfig{}, nil
	case sqlitevault.TypeUnsafe:
		return &sqlitevault.FileConfig{}, nil
	case openbaovault.TypeOpenBao:
		return &openbaovault.Config{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", vault.ErrUnknownType, t)
	}
}
