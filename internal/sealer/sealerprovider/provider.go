package sealerprovider

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/providertest"
	"github.com/openkcm/krypton/internal/sealer/staticsecret"
	"github.com/openkcm/krypton/internal/secret/secretprovider"
)

var ErrSealerNameEmpty = errors.New("sealer name is empty")

// Spec describes which sealer implementation to use and how to configure it.
type Spec struct { //nolint:recvcheck // MarshalYAML must support values while the remaining methods use pointers.
	Name string      `yaml:"name"`
	Type sealer.Type `yaml:"type"`
	// Config and Auth are marshaled/unmarshaled via custom MarshalYAML/UnmarshalYAML, not by the default YAML codec.
	Config sealer.SealerConfig `yaml:"-"`
	Auth   sealer.SealerAuth   `yaml:"-"`
}

var (
	_ yaml.Unmarshaler = (*Spec)(nil)
	_ yaml.Marshaler   = Spec{}
)

// MarshalYAML implements [yaml.Marshaler]. It uses a value receiver so the
// custom marshaling also applies when a Spec is held by value.
func (s Spec) MarshalYAML() (any, error) {
	type alias Spec
	return struct {
		alias `yaml:",inline"`

		Auth   sealer.SealerAuth   `yaml:"auth,omitempty"`
		Config sealer.SealerConfig `yaml:"config,omitempty"`
	}{
		alias:  alias(s),
		Auth:   s.Auth,
		Config: s.Config,
	}, nil
}

// UnmarshalYAML implements [yaml.Unmarshaler].
func (s *Spec) UnmarshalYAML(node *yaml.Node) error {
	type alias Spec
	var raw struct {
		alias `yaml:",inline"`

		Auth   yaml.Node `yaml:"auth"`
		Config yaml.Node `yaml:"config"`
	}
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("failed to decode sealer spec: %w", err)
	}

	cfg, auth, err := newSealer(raw.Type)
	if err != nil {
		return err
	}

	if raw.Config.Kind != 0 {
		if err := raw.Config.Decode(cfg); err != nil {
			return fmt.Errorf("failed to decode sealer config: %w", err)
		}
	}

	if raw.Auth.Kind != 0 {
		if err := raw.Auth.Decode(auth); err != nil {
			return fmt.Errorf("failed to decode sealer auth: %w", err)
		}
	}

	*s = Spec(raw.alias)
	s.Config = cfg
	s.Auth = auth
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
	if s.Auth != nil {
		if err := s.Auth.ValidateSealerAuth(); err != nil {
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
	case *providertest.Config:
		auth, ok := spec.Auth.(*providertest.Auth)
		if !ok || auth == nil {
			return nil, fmt.Errorf("invalid auth for sealer %q: %T", spec.Name, spec.Auth)
		}
		return providertest.NewClient(*cfg, *auth)
	default:
		return nil, fmt.Errorf("%w: %T", sealer.ErrUnknownType, spec.Config)
	}
}

// ValidateType reports whether t is a known/supported sealer type.
func ValidateType(t sealer.Type) error {
	_, _, err := newSealer(t)
	return err
}

// newSealer is a factory that creates the correct SealerConfig and SealerAuth
// structs by sealer type.
func newSealer(t sealer.Type) (sealer.SealerConfig, sealer.SealerAuth, error) {
	switch t {
	case staticsecret.TypeStaticSecret:
		return &staticsecret.Config{}, &staticsecret.Auth{}, nil
	case providertest.TypeProviderTest:
		return &providertest.Config{}, &providertest.Auth{}, nil
	default:
		return nil, nil, fmt.Errorf("%w: %q", sealer.ErrUnknownType, t)
	}
}
