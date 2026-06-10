package spec

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
)

type VaultSpec struct {
	Name   string       `yaml:"name"`
	Type   vault.Type   `yaml:"type"`
	Config vault.Config `yaml:"-"`
}

var (
	_ yaml.Unmarshaler = (*VaultSpec)(nil)
	_ yaml.Marshaler   = (*VaultSpec)(nil)
)

func (v *VaultSpec) Validate() error {
	if v.Name == "" {
		return ErrVaultNameEmpty
	}
	if v.Config != nil {
		if err := v.Config.ValidateVaultConfig(); err != nil {
			return err
		}
	}
	return nil
}

func (v *VaultSpec) Open(ctx context.Context) (vault.Vault, error) {
	switch c := v.Config.(type) {
	case *sqlitevault.UnsafeConfig:
		return sqlitevault.NewUnsafe(ctx, v.Name, sqlitevault.FileSource(c.Path))
	case *sqlitevault.UnsafeMemoryConfig:
		return sqlitevault.NewUnsafe(ctx, v.Name, sqlitevault.MemorySource)
	default:
		return nil, fmt.Errorf("%w: %T", vault.ErrUnknownType, v.Config)
	}
}

func (v *VaultSpec) MarshalYAML() (any, error) {
	type alias VaultSpec
	return struct {
		alias `yaml:",inline"`

		Config vault.Config `yaml:"config"`
	}{
		alias:  alias(*v),
		Config: v.Config,
	}, nil
}

func (v *VaultSpec) UnmarshalYAML(node *yaml.Node) error {
	type alias VaultSpec
	var raw struct {
		alias `yaml:",inline"`

		Config yaml.Node `yaml:"config"`
	}
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode vault spec: %w", err)
	}

	config, err := newVaultConfig(raw.Type)
	if err != nil {
		return err
	}

	if raw.Config.Kind != 0 {
		if err := raw.Config.Decode(config); err != nil {
			return fmt.Errorf("failed to decode vault config: %w", err)
		}
	}

	*v = VaultSpec(raw.alias)
	v.Config = config
	return nil
}

func newVaultConfig(t vault.Type) (vault.Config, error) {
	switch t {
	case sqlitevault.TypeUnsafe:
		return &sqlitevault.UnsafeConfig{}, nil
	case sqlitevault.TypeUnsafeMemory:
		return &sqlitevault.UnsafeMemoryConfig{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", vault.ErrUnknownType, t)
	}
}
