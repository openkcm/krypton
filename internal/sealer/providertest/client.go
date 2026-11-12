package providertest

import (
	"context"

	"github.com/openkcm/krypton/internal/sealer"
)

// TypeProviderTest identifies the test provider.
const TypeProviderTest sealer.Type = "providertest"

// Auth contains provider client authentication.
type Auth struct {
	Token AccessToken `yaml:"access_token"`
}

var _ sealer.SealerAuth = (*Auth)(nil)

// ValidateSealerAuth validates the authentication.
func (m *Auth) ValidateSealerAuth() error {
	if m == nil || m.Token == "" {
		return ErrAccessTokenMissing
	}
	return nil
}

// Config identifies a provider instance.
type Config struct {
	InstanceID string `yaml:"instance_id"`
}

var _ sealer.SealerConfig = (*Config)(nil)

// ValidateSealerConfig validates the configuration.
func (m *Config) ValidateSealerConfig() error {
	if m == nil || m.InstanceID == "" {
		return ErrInstanceIDMissing
	}
	return nil
}

// Client binds a provider instance and access token to the Sealer interface.
type Client struct {
	provider   *Provider
	instanceID string
	token      AccessToken
}

var _ sealer.Sealer = (*Client)(nil)

// NewClient creates a client bound to one provider instance.
func NewClient(config Config, auth Auth) (*Client, error) {
	if err := config.ValidateSealerConfig(); err != nil {
		return nil, err
	}
	if err := auth.ValidateSealerAuth(); err != nil {
		return nil, err
	}

	provider, err := New()
	if err != nil {
		return nil, err
	}
	if _, err := provider.resolveInstancePath(config.InstanceID); err != nil {
		return nil, err
	}

	return &Client{
		provider:   provider,
		instanceID: config.InstanceID,
		token:      auth.Token,
	}, nil
}

// Seal encrypts plaintext with a provider key.
func (m *Client) Seal(ctx context.Context, req sealer.SealRequest) (sealer.SealResponse, error) {
	keyID, err := keyIDFromMetadata(req.Metadata)
	if err != nil {
		return sealer.SealResponse{}, err
	}

	ciphertext, err := m.provider.seal(ctx, sealParams{
		instanceID: m.instanceID,
		keyID:      keyID,
		token:      m.token,
		plaintext:  req.Plaintext,
		aad:        req.AAD,
	})
	if err != nil {
		return sealer.SealResponse{}, err
	}
	return sealer.SealResponse{Ciphertext: ciphertext}, nil
}

// Unseal decrypts ciphertext with a provider key.
func (m *Client) Unseal(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
	keyID, err := keyIDFromMetadata(req.Metadata)
	if err != nil {
		return sealer.UnsealResponse{}, err
	}

	plaintext, err := m.provider.unseal(ctx, unsealParams{
		instanceID: m.instanceID,
		keyID:      keyID,
		token:      m.token,
		ciphertext: req.Ciphertext,
		aad:        req.AAD,
	})
	if err != nil {
		return sealer.UnsealResponse{}, err
	}
	return sealer.UnsealResponse{Plaintext: plaintext}, nil
}

func keyIDFromMetadata(metadata map[string]string) (string, error) {
	keyID := metadata[sealer.ProviderKeyMetadataKey(TypeProviderTest)]
	if keyID == "" {
		return "", ErrKeyIDMissing
	}
	return keyID, nil
}
