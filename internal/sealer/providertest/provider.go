// Package providertest provides an opinionated AES-256-GCM provider with key-scoped
// access-token auth backed by unsafe in-memory SQLite. It is for testing only.
package providertest

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"uuid"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
)

// TypeProviderTest identifies the test provider.
const TypeProviderTest sealer.Type = "providertest"

const providerID = "providertest"

var (
	ErrAccessTokenMissing = errors.New("access token is missing")
	ErrAuthNotFound       = errors.New("provider auth not found")
	ErrUnauthorized       = errors.New("invalid access token")
	ErrInvalidKeyRef      = errors.New("invalid provider key reference, expected <tenant-id>:<key-id>:<version>")
	ErrKeyRefMissing      = errors.New("provider key reference is missing")
	ErrKeyNotFound        = errors.New("provider key not found")
)

// AccessToken authenticates a provider client.
type AccessToken string

// KeyRef identifies one version of a provider key.
type KeyRef struct {
	TenantID string
	KeyID    string
	Version  int
}

// String returns the string representation of the key reference.
func (m KeyRef) String() string {
	return m.TenantID + ":" + m.KeyID + ":" + strconv.Itoa(m.Version)
}

// ParseKeyRef parses a key reference string.
func ParseKeyRef(value string) (KeyRef, error) {
	if value == "" {
		return KeyRef{}, ErrKeyRefMissing
	}

	tenantID, remainder, ok := strings.Cut(value, ":")
	if !ok || tenantID != providerID {
		return KeyRef{}, ErrInvalidKeyRef
	}

	keyID, rawVersion, ok := strings.Cut(remainder, ":")
	if !ok || keyID == "" {
		return KeyRef{}, ErrInvalidKeyRef
	}

	version, err := strconv.Atoi(rawVersion)
	if err != nil || version < 1 {
		return KeyRef{}, ErrInvalidKeyRef
	}

	return KeyRef{
		TenantID: tenantID,
		KeyID:    keyID,
		Version:  version,
	}, nil
}

// Auth contains provider client auth.
type Auth struct {
	Token AccessToken `yaml:"access_token"`
}

var _ sealer.SealerAuth = (*Auth)(nil)

// ValidateSealerAuth validates the auth.
func (m *Auth) ValidateSealerAuth() error {
	if m == nil || m.Token == "" {
		return ErrAccessTokenMissing
	}
	return nil
}

// Config configures the test provider.
type Config struct{}

var _ sealer.SealerConfig = (*Config)(nil)

// ValidateSealerConfig validates the configuration.
func (m *Config) ValidateSealerConfig() error {
	return nil
}

// Provider manages test keys and auth.
type Provider struct {
	vault  *sqlitevault.Unsafe
	mu     sync.Mutex
	latest map[string]int
}

// New opens the shared in-memory provider.
func New(ctx context.Context) (*Provider, error) {
	v, err := sqlitevault.NewUnsafe(ctx, providerID, sqlitevault.MemorySource)
	if err != nil {
		return nil, err
	}

	return &Provider{
		vault:  v,
		latest: make(map[string]int),
	}, nil
}

// Close closes the provider.
func (m *Provider) Close() error {
	return m.vault.Close()
}

// CreateKey creates a key and its auth.
func (m *Provider) CreateKey(ctx context.Context) (Auth, KeyRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	keyID := uuid.New().String()

	keyMaterial, err := randomData("providertest-key", aes256gcm.KeySize)
	if err != nil {
		return Auth{}, KeyRef{}, err
	}
	defer keyMaterial.Destroy()

	authSecret, err := randomData("providertest-access-token", 32)
	if err != nil {
		return Auth{}, KeyRef{}, err
	}
	defer authSecret.Destroy()

	_, err = m.vault.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: providerID,
		ID:       keySecretID(keyID),
		Version:  1,
		Secret:   keyMaterial,
	})
	if err != nil {
		return Auth{}, KeyRef{}, err
	}

	_, err = m.vault.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: providerID,
		ID:       authSecretID(keyID),
		Secret:   authSecret,
	})
	if err != nil {
		return Auth{}, KeyRef{}, err
	}

	keyRef := KeyRef{
		TenantID: providerID,
		KeyID:    keyID,
		Version:  1,
	}
	m.latest[keyID] = keyRef.Version

	return newAuth(authSecret), keyRef, nil
}

// RotateAuth replaces the auth for a key.
func (m *Provider) RotateAuth(ctx context.Context, keyID string) (Auth, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current, err := m.vault.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: providerID,
		ID:       authSecretID(keyID),
	})
	if errors.Is(err, vault.ErrSecretNotFound) {
		return Auth{}, ErrAuthNotFound
	}
	if err != nil {
		return Auth{}, err
	}
	defer current.Secret.Destroy()

	secret, err := randomData("providertest-access-token", 32)
	if err != nil {
		return Auth{}, err
	}
	defer secret.Destroy()

	_, err = m.vault.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: providerID,
		ID:       authSecretID(keyID),
		Secret:   secret,
	})
	if err != nil {
		return Auth{}, err
	}

	return newAuth(secret), nil
}

// RotateKey creates the next version of a key.
func (m *Provider) RotateKey(ctx context.Context, keyID string) (KeyRef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	current, ok := m.latest[keyID]
	if !ok {
		return KeyRef{}, ErrKeyNotFound
	}
	next := current + 1

	keyMaterial, err := randomData("providertest-key", aes256gcm.KeySize)
	if err != nil {
		return KeyRef{}, err
	}
	defer keyMaterial.Destroy()

	_, err = m.vault.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: providerID,
		ID:       keySecretID(keyID),
		Version:  next,
		Secret:   keyMaterial,
	})
	if err != nil {
		return KeyRef{}, err
	}
	m.latest[keyID] = next

	return KeyRef{
		TenantID: providerID,
		KeyID:    keyID,
		Version:  next,
	}, nil
}

// DestroyKey removes a key, its versions, and auth.
func (m *Provider) DestroyKey(ctx context.Context, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	latest, ok := m.latest[keyID]
	if !ok {
		return ErrKeyNotFound
	}

	for version := 1; version <= latest; version++ {
		_, err := m.vault.DestroySecret(ctx, vault.DestroySecretRequest{
			TenantID: providerID,
			ID:       keySecretID(keyID),
			Version:  version,
		})
		if err != nil {
			return err
		}
	}

	_, err := m.vault.DestroySecret(ctx, vault.DestroySecretRequest{
		TenantID: providerID,
		ID:       authSecretID(keyID),
	})
	if err != nil {
		return err
	}

	delete(m.latest, keyID)
	return nil
}

// Client seals data with authenticated provider keys.
type Client struct {
	vault   *sqlitevault.Unsafe
	auth    Auth
	cryptor *aes256gcm.AES256GCM
}

var _ sealer.Sealer = (*Client)(nil)

// NewClient opens an authenticated provider client.
func NewClient(ctx context.Context, auth Auth) (*Client, error) {
	if err := auth.ValidateSealerAuth(); err != nil {
		return nil, err
	}

	v, err := sqlitevault.NewUnsafe(ctx, providerID, sqlitevault.MemorySource)
	if err != nil {
		return nil, err
	}

	return &Client{
		vault:   v,
		auth:    auth,
		cryptor: aes256gcm.New(providerID),
	}, nil
}

// Close closes the client.
func (m *Client) Close() error {
	return m.vault.Close()
}

// Seal encrypts plaintext with a provider key.
func (m *Client) Seal(ctx context.Context, req sealer.SealRequest) (sealer.SealResponse, error) {
	keyRef, err := ParseKeyRef(req.Metadata[sealer.ProviderKeyMetadataKey(TypeProviderTest)])
	if err != nil {
		return sealer.SealResponse{}, err
	}

	if err := m.authenticate(ctx, keyRef); err != nil {
		return sealer.SealResponse{}, err
	}

	keyMaterial, err := m.exportKeyMaterial(ctx, keyRef)
	if err != nil {
		return sealer.SealResponse{}, err
	}
	defer keyMaterial.Destroy()

	resp, err := m.cryptor.Encrypt(ctx, cryptor.EncryptRequest{
		Secret: cryptor.Secret{
			Data:      keyMaterial,
			Algorithm: cryptor.KeyAlgorithmAES256,
		},
		Plaintext: req.Plaintext,
		AAD:       req.AAD,
	})
	if err != nil {
		return sealer.SealResponse{}, err
	}

	return sealer.SealResponse{
		Ciphertext: resp.Ciphertext,
	}, nil
}

// Unseal decrypts ciphertext with a provider key.
func (m *Client) Unseal(ctx context.Context, req sealer.UnsealRequest) (sealer.UnsealResponse, error) {
	keyRef, err := ParseKeyRef(req.Metadata[sealer.ProviderKeyMetadataKey(TypeProviderTest)])
	if err != nil {
		return sealer.UnsealResponse{}, err
	}

	if err := m.authenticate(ctx, keyRef); err != nil {
		return sealer.UnsealResponse{}, err
	}

	keyMaterial, err := m.exportKeyMaterial(ctx, keyRef)
	if err != nil {
		return sealer.UnsealResponse{}, err
	}
	defer keyMaterial.Destroy()

	resp, err := m.cryptor.Decrypt(ctx, cryptor.DecryptRequest{
		Secret: cryptor.Secret{
			Data:      keyMaterial,
			Algorithm: cryptor.KeyAlgorithmAES256,
		},
		Ciphertext: req.Ciphertext,
		AAD:        req.AAD,
	})
	if err != nil {
		return sealer.UnsealResponse{}, err
	}

	return sealer.UnsealResponse{
		Plaintext: resp.Plaintext,
	}, nil
}

func (m *Client) exportKeyMaterial(ctx context.Context, keyRef KeyRef) (*securemem.Data, error) {
	resp, err := m.vault.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: keyRef.TenantID,
		ID:       keySecretID(keyRef.KeyID),
		Version:  keyRef.Version,
	})
	if err != nil {
		return nil, err
	}

	return resp.Secret, nil
}

func (m *Client) authenticate(ctx context.Context, keyRef KeyRef) error {
	resp, err := m.vault.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: keyRef.TenantID,
		ID:       authSecretID(keyRef.KeyID),
	})
	if errors.Is(err, vault.ErrSecretNotFound) {
		return ErrAuthNotFound
	}
	if err != nil {
		return err
	}
	defer resp.Secret.Destroy()

	provided, err := base64.RawURLEncoding.DecodeString(string(m.auth.Token))
	if err != nil {
		return ErrUnauthorized
	}
	defer securemem.Zero(provided)

	if subtle.ConstantTimeCompare(resp.Secret.SecureBytes(), provided) != 1 {
		return ErrUnauthorized
	}

	return nil
}

func newAuth(secret *securemem.Data) Auth {
	return Auth{
		Token: AccessToken(base64.RawURLEncoding.EncodeToString(secret.SecureBytes())),
	}
}

func randomData(name string, size int) (*securemem.Data, error) {
	data, err := securemem.NewData(name, size)
	if err != nil {
		return nil, err
	}

	rand.Read(data.SecureBytes())
	return data, nil
}

func keySecretID(id string) string {
	return "key:" + id
}

func authSecretID(id string) string {
	return "auth:" + id
}
