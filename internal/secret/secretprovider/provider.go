package secretprovider

import (
	"context"
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/secret"
	"github.com/openkcm/krypton/internal/secret/envvar"
	"github.com/openkcm/krypton/internal/securemem"
)

var ErrUnknownType = errors.New("unknown secret source type")

// Spec describes which secret source implementation to use and how to configure it.
type Spec struct {
	Type   secret.Type   `yaml:"type"`
	Config secret.Config `yaml:"-"`
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

		Config secret.Config `yaml:"config"`
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
		return fmt.Errorf("failed to decode secret source spec: %w", err)
	}

	cfg, err := newConfig(raw.Type)
	if err != nil {
		return err
	}

	if raw.Config.Kind != 0 {
		if err := raw.Config.Decode(cfg); err != nil {
			return fmt.Errorf("failed to decode secret source config: %w", err)
		}
	}

	*s = Spec(raw.alias)
	s.Config = cfg
	return nil
}

// Validate checks the Spec for structural correctness.
func (s *Spec) Validate() error {
	if s.Type == "" {
		return fmt.Errorf("%w: type is empty", ErrUnknownType)
	}
	if s.Config != nil {
		return s.Config.ValidateSecretConfig()
	}
	return nil
}

// GetSecret creates the appropriate Loader from the Spec and loads the secret.
func GetSecret(ctx context.Context, spec Spec) (*securemem.Data, error) {
	loader, err := newLoader(spec)
	if err != nil {
		return nil, err
	}
	return loader.LoadSecret(ctx)
}

// newLoader constructs the appropriate Loader bound to its config.
func newLoader(spec Spec) (secret.Loader, error) {
	switch spec.Type {
	case envvar.Type:
		cfg, ok := spec.Config.(*envvar.Config)
		if !ok {
			return nil, fmt.Errorf("expected *envvar.Config for type %q, got %T", spec.Type, spec.Config)
		}
		return envvar.New(cfg), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, spec.Type)
	}
}

// newConfig is a factory that creates the correct Config struct by source type.
func newConfig(t secret.Type) (secret.Config, error) {
	switch t {
	case envvar.Type:
		return &envvar.Config{}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownType, t)
	}
}
