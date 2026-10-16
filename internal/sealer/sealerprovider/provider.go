package sealerprovider

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
)

var ErrSealerNameEmpty = errors.New("sealer name is empty")

// Spec describes which sealer implementation to use and how to configure it.
type Spec struct {
	Name string      `yaml:"name"`
	Type sealer.Type `yaml:"type"`
	// Config is marshaled/unmarshaled via custom MarshalYAML/UnmarshalYAML, not by the default YAML codec.
	Config sealer.SealerConfig `yaml:"-"`
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

		Config sealer.SealerConfig `yaml:"config,omitempty"`
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
		return fmt.Errorf("failed to decode sealer spec: %w", err)
	}

	cfg, err := newSealerConfig(raw.Type)
	if err != nil {
		return err
	}

	if raw.Config.Kind != 0 {
		if err := raw.Config.Decode(cfg); err != nil {
			return fmt.Errorf("failed to decode sealer config: %w", err)
		}
	}

	*s = Spec(raw.alias)
	s.Config = cfg
	return nil
}

// Validate checks the Spec for structural correctness.
func (s *Spec) Validate() error {
	if s.Name == "" {
		return ErrSealerNameEmpty
	}
	if s.Config != nil {
		if err := s.Config.ValidateSealerConfig(); err != nil {
			return err
		}
	}
	return nil
}

// GetSealer constructs a ready-to-use sealer.Sealer from the given Spec.
func GetSealer(ctx context.Context, spec Spec) (sealer.Sealer, error) {
	switch cfg := spec.Config.(type) {
	case *staticsecret.Config:
		secret, err := secretprovider.GetSecret(ctx, cfg.Secret)
		if err != nil {
			return nil, fmt.Errorf("failed to load secret for sealer %q: %w", spec.Name, err)
		}
		return staticsecret.New(spec.Name, secret)
	default:
		return nil, fmt.Errorf("%w: %T", sealer.ErrUnknownType, spec.Config)
	}
}

// newSealerConfig is a factory that creates the correct SealerConfig struct by sealer type.
func newSealerConfig(t sealer.Type) (sealer.SealerConfig, error) {
	switch t {
	case staticsecret.TypeStaticSecret:
		return &staticsecret.Config{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", sealer.ErrUnknownType, t)
	}
}
