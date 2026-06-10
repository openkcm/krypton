package spec

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
)

type CryptorSpec struct {
	Name   string         `yaml:"name"`
	Type   cryptor.Type   `yaml:"type"`
	Config cryptor.Config `yaml:"-"`
}

var (
	_ yaml.Unmarshaler = (*CryptorSpec)(nil)
	_ yaml.Marshaler   = (*CryptorSpec)(nil)
)

type CryptorBundle struct {
	Cryptor         cryptor.Cryptor
	SecretGenerator cryptor.SecretGenerator
}

func (c *CryptorSpec) Validate() error {
	if c.Name == "" {
		return ErrCryptorNameEmpty
	}
	if c.Config != nil {
		if err := c.Config.ValidateCryptorConfig(); err != nil {
			return err
		}
	}
	return nil
}

func (c *CryptorSpec) Open(ctx context.Context) (CryptorBundle, error) {
	switch c.Config.(type) {
	case *aes256gcm.CryptorConfig:
		return CryptorBundle{
			Cryptor:         aes256gcm.New(),
			SecretGenerator: cryptor.NewAES256SecretGenerator(),
		}, nil
	case *staticsecret.CryptorConfig:
		// This simulates an internally-managed HSM key
		sg := cryptor.NewAES256SecretGenerator()
		gen, err := sg.GenerateSecret(ctx)
		if err != nil {
			return CryptorBundle{}, err
		}
		cr, err := staticsecret.New(staticsecret.InfoNameStaticSecret, gen.Secret)
		if err != nil {
			return CryptorBundle{}, err
		}
		return CryptorBundle{Cryptor: cr}, nil
	default:
		return CryptorBundle{}, fmt.Errorf("%w: %T", cryptor.ErrUnknownType, c.Config)
	}
}

func (c *CryptorSpec) MarshalYAML() (any, error) {
	type alias CryptorSpec
	return struct {
		alias `yaml:",inline"`

		Config cryptor.Config `yaml:"config"`
	}{
		alias:  alias(*c),
		Config: c.Config,
	}, nil
}

func (c *CryptorSpec) UnmarshalYAML(node *yaml.Node) error {
	type alias CryptorSpec
	var raw struct {
		alias `yaml:",inline"`

		Config yaml.Node `yaml:"config"`
	}
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode cryptor spec: %w", err)
	}

	cfg, err := newCryptorConfig(raw.Type)
	if err != nil {
		return err
	}

	if raw.Config.Kind != 0 {
		if err := raw.Config.Decode(cfg); err != nil {
			return fmt.Errorf("failed to decode cryptor config: %w", err)
		}
	}

	*c = CryptorSpec(raw.alias)
	c.Config = cfg
	return nil
}

func newCryptorConfig(t cryptor.Type) (cryptor.Config, error) {
	switch t {
	case aes256gcm.TypeAES256GCM:
		return &aes256gcm.CryptorConfig{}, nil
	case staticsecret.TypeHSM:
		return &staticsecret.CryptorConfig{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", cryptor.ErrUnknownType, t)
	}
}
