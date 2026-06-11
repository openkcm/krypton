package cryptorprovider

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
)

var ErrCryptorNameEmpty = errors.New("cryptor name is empty")

// Spec describes which cryptor implementation to use and how to configure it.
type Spec struct {
	Name   string         `yaml:"name"`
	Type   cryptor.Type   `yaml:"type"`
	Config cryptor.Config `yaml:"-"`
}

var (
	_ yaml.Unmarshaler = (*Spec)(nil)
	_ yaml.Marshaler   = (*Spec)(nil)
)

func (s *Spec) MarshalYAML() (any, error) {
	type alias Spec
	return struct {
		alias `yaml:",inline"`

		Config cryptor.Config `yaml:"config"`
	}{
		alias:  alias(*s),
		Config: s.Config,
	}, nil
}

func (s *Spec) UnmarshalYAML(node *yaml.Node) error {
	type alias Spec
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

	*s = Spec(raw.alias)
	s.Config = cfg
	return nil
}

// Validate checks the Spec for structural correctness.
func (s *Spec) Validate() error {
	if s.Name == "" {
		return ErrCryptorNameEmpty
	}
	if s.Config != nil {
		if err := s.Config.ValidateCryptorConfig(); err != nil {
			return err
		}
	}
	return nil
}

// GetBundle constructs a ready-to-use cryptor Bundle from the given Spec.
func GetBundle(ctx context.Context, spec Spec) (cryptor.Bundle, error) {
	switch c := spec.Config.(type) {
	case *aes256gcm.Config:
		_ = c // no config fields to use
		return cryptor.Bundle{
			Cryptor:         aes256gcm.New(spec.Name),
			SecretGenerator: cryptor.NewAES256SecretGenerator(),
		}, nil
	case *staticsecret.Config:
		secret, err := getSecret(ctx, c)
		if err != nil {
			return cryptor.Bundle{}, err
		}
		cryp, err := staticsecret.New(spec.Name, secret.Data)
		if err != nil {
			return cryptor.Bundle{}, err
		}
		return cryptor.Bundle{
			Cryptor: cryp,
		}, nil
	default:
		return cryptor.Bundle{}, fmt.Errorf("%w: %T", cryptor.ErrUnknownType, spec.Config)
	}
}

// newCryptorConfig is a factory that creates the correct Config struct by cryptor type.
func newCryptorConfig(t cryptor.Type) (cryptor.Config, error) {
	switch t {
	case aes256gcm.TypeAES256GCM:
		return &aes256gcm.Config{}, nil
	case staticsecret.TypeStaticSecret:
		return &staticsecret.Config{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", cryptor.ErrUnknownType, t)
	}
}

// getSecret gets the cryptor secret for a static-secret cryptor via the configured secret source.
func getSecret(ctx context.Context, cfg *staticsecret.Config) (cryptor.Secret, error) {
	data, err := secretprovider.GetSecret(ctx, cfg.Secret)
	if err != nil {
		return cryptor.Secret{}, err
	}
	return cryptor.Secret{
		Algorithm: cryptor.KeyAlgorithmAES256,
		Data:      data,
	}, nil
}
