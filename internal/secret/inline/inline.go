package inline

import (
	"context"
	"encoding/base64"
	"errors"

	"gopkg.in/yaml.v3"

	"github.com/openkcm/krypton/internal/secret"
	"github.com/openkcm/krypton/internal/securemem"
)

const Type secret.Type = "inline"

const memKey = "inline-secret"

var ErrMaterialMissing = errors.New("inline secret material is missing")

type Config struct {
	Material *securemem.Data `yaml:"material"`
}

var (
	_ secret.Config    = (*Config)(nil)
	_ secret.Destroyer = (*Config)(nil)
	_ yaml.Marshaler   = (*Config)(nil)
	_ yaml.Unmarshaler = (*Config)(nil)
)

func (c *Config) ValidateSecretConfig() error {
	if c.Material == nil || len(c.Material.SecureBytes()) == 0 {
		return ErrMaterialMissing
	}
	return nil
}

func (c *Config) MarshalYAML() (any, error) {
	if c.Material == nil {
		return nil, ErrMaterialMissing
	}
	src := c.Material.SecureBytes()
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(src)))
	defer securemem.Zero(buf)
	base64.StdEncoding.Encode(buf, src)
	return struct {
		Material string `yaml:"material"`
	}{Material: string(buf)}, nil
}

func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	var raw struct {
		Material string `yaml:"material"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.Material == "" {
		return ErrMaterialMissing
	}

	decoded, err := base64.StdEncoding.DecodeString(raw.Material)
	if err != nil {
		return err
	}
	defer securemem.Zero(decoded)

	data, err := securemem.NewData(memKey, len(decoded))
	if err != nil {
		return err
	}
	copy(data.SecureBytes(), decoded)

	c.Material = data
	return nil
}

func (c *Config) DestroySecret() error {
	return c.Material.Destroy()
}

type Loader struct {
	cfg *Config
}

var _ secret.Loader = (*Loader)(nil)

func New(cfg *Config) *Loader {
	return &Loader{cfg: cfg}
}

func (l *Loader) LoadSecret(ctx context.Context) (*securemem.Data, error) {
	if l.cfg == nil || l.cfg.Material == nil || len(l.cfg.Material.SecureBytes()) == 0 {
		return nil, ErrMaterialMissing
	}
	return l.cfg.Material, nil
}
