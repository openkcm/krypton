// Package providertest provides an AES-256-GCM provider with key-scoped
// access-token auth backed by unsafe file-based SQLite. It is for testing only.
package providertest

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/aes256gcm"
	"github.com/openkcm/krypton/internal/securemem"
	"github.com/openkcm/krypton/internal/vault"
	"github.com/openkcm/krypton/internal/vault/sqlitevault"
)

const singleTenantID = "providertest"

// Environment variables that enable and configure the unsafe test provider.
const (
	EnableEnv    = "ENABLE_UNSAFE_TEST_PROVIDER"
	EnableAck    = "I_ACCEPT"
	DirectoryEnv = "UNSAFE_TEST_PROVIDER_DIR"
)

var (
	ErrAccessTokenMissing      = errors.New("access token is missing")
	ErrAuthNotFound            = errors.New("provider auth not found")
	ErrInstanceIDMissing       = errors.New("provider instance ID is missing")
	ErrInstanceNotFound        = errors.New("provider instance not found")
	ErrKeyIDMissing            = errors.New("provider key ID is missing")
	ErrKeyNotFound             = errors.New("provider key not found")
	ErrProviderDisabled        = errors.New("unsafe test provider is disabled")
	ErrStorageDirectoryMissing = errors.New("provider storage directory is missing")
	ErrUnauthorized            = errors.New("invalid access token")
)

// AccessToken authenticates a client for one provider key.
type AccessToken string

// Provider manages provider instances, keys, authentication, and encryption.
type Provider struct {
	dir       string
	cryptor   *aes256gcm.AES256GCM
	generator cryptor.SecretGenerator
}

// IsEnabled reports whether unsafe test-provider registration was requested.
func IsEnabled() bool {
	_, set := os.LookupEnv(EnableEnv)
	return set
}

// New creates a provider from the unsafe test-provider environment settings.
func New() (*Provider, error) {
	dir, err := loadDirectory()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}

	return &Provider{
		dir:       dir,
		cryptor:   aes256gcm.New(singleTenantID),
		generator: cryptor.NewAES256SecretGenerator(),
	}, nil
}

// UpsertInstance creates an instance database if it does not exist.
func (m *Provider) UpsertInstance(ctx context.Context, instanceID string) error {
	v, err := m.openOrCreateInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	return v.Close()
}

// UpsertKey generates and stores AES-256 material in an existing instance.
func (m *Provider) UpsertKey(ctx context.Context, instanceID, keyID string) error {
	if keyID == "" {
		return ErrKeyIDMissing
	}

	v, err := m.openInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	defer v.Close()

	generated, err := m.generator.GenerateSecret(ctx)
	if err != nil {
		return err
	}
	defer generated.Secret.Destroy()

	_, err = v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: singleTenantID,
		ID:       keySecretID(keyID),
		Secret:   generated.Secret,
	})
	return err
}

// UpsertKeyAuth stores key-bound authentication in an existing instance.
func (m *Provider) UpsertKeyAuth(ctx context.Context, instanceID, keyID string, token AccessToken) error {
	if keyID == "" {
		return ErrKeyIDMissing
	}
	if token == "" {
		return ErrAccessTokenMissing
	}

	v, err := m.openInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	defer v.Close()

	secret, err := securemem.NewData("providertest-access-token", len(token))
	if err != nil {
		return err
	}
	defer secret.Destroy()
	copy(secret.SecureBytes(), string(token))

	_, err = v.ImportSecret(ctx, vault.ImportSecretRequest{
		TenantID: singleTenantID,
		ID:       authSecretID(keyID),
		Secret:   secret,
	})
	return err
}

// DeleteInstance removes an instance database.
func (m *Provider) DeleteInstance(instanceID string) error {
	path, err := m.instancePath(instanceID)
	if err != nil {
		return err
	}

	if err := os.Remove(path); errors.Is(err, os.ErrNotExist) {
		return ErrInstanceNotFound
	} else {
		return err
	}
}

type sealParams struct {
	instanceID string
	keyID      string
	token      AccessToken
	plaintext  *securemem.Data
	aad        []byte
}

type unsealParams struct {
	instanceID string
	keyID      string
	token      AccessToken
	ciphertext *securemem.Data
	aad        []byte
}

func (m *Provider) seal(ctx context.Context, p sealParams) (*securemem.Data, error) {
	keyMaterial, err := m.loadKeyMaterial(ctx, p.instanceID, p.keyID, p.token)
	if err != nil {
		return nil, err
	}
	defer keyMaterial.Destroy()

	resp, err := m.cryptor.Encrypt(ctx, cryptor.EncryptRequest{
		Secret: cryptor.Secret{
			Data:      keyMaterial,
			Algorithm: cryptor.KeyAlgorithmAES256,
		},
		Plaintext: p.plaintext,
		AAD:       p.aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (m *Provider) unseal(ctx context.Context, p unsealParams) (*securemem.Data, error) {
	keyMaterial, err := m.loadKeyMaterial(ctx, p.instanceID, p.keyID, p.token)
	if err != nil {
		return nil, err
	}
	defer keyMaterial.Destroy()

	resp, err := m.cryptor.Decrypt(ctx, cryptor.DecryptRequest{
		Secret: cryptor.Secret{
			Data:      keyMaterial,
			Algorithm: cryptor.KeyAlgorithmAES256,
		},
		Ciphertext: p.ciphertext,
		AAD:        p.aad,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (m *Provider) loadKeyMaterial(ctx context.Context, instanceID, keyID string, token AccessToken) (*securemem.Data, error) {
	v, err := m.authenticate(ctx, instanceID, keyID, token)
	if err != nil {
		return nil, err
	}
	defer v.Close()

	resp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: singleTenantID,
		ID:       keySecretID(keyID),
	})
	if errors.Is(err, vault.ErrSecretNotFound) {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return resp.Secret, nil
}

func (m *Provider) authenticate(ctx context.Context, instanceID, keyID string, token AccessToken) (*sqlitevault.Unsafe, error) {
	v, err := m.openInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	resp, err := v.ExportSecret(ctx, vault.ExportSecretRequest{
		TenantID: singleTenantID,
		ID:       authSecretID(keyID),
	})
	if errors.Is(err, vault.ErrSecretNotFound) {
		_ = v.Close()
		return nil, ErrAuthNotFound
	}
	if err != nil {
		_ = v.Close()
		return nil, err
	}
	defer resp.Secret.Destroy()

	provided := []byte(token)
	defer securemem.Zero(provided)
	if subtle.ConstantTimeCompare(resp.Secret.SecureBytes(), provided) != 1 {
		_ = v.Close()
		return nil, ErrUnauthorized
	}
	return v, nil
}

func loadDirectory() (string, error) {
	value, set := os.LookupEnv(EnableEnv)
	if !set {
		return "", ErrProviderDisabled
	}
	if value != EnableAck {
		return "", fmt.Errorf("%s must be set to %s", EnableEnv, EnableAck)
	}

	dir := os.Getenv(DirectoryEnv)
	if dir == "" {
		return "", ErrStorageDirectoryMissing
	}
	return dir, nil
}

func (m *Provider) openOrCreateInstance(ctx context.Context, instanceID string) (*sqlitevault.Unsafe, error) {
	path, err := m.instancePath(instanceID)
	if err != nil {
		return nil, err
	}
	return openVault(ctx, instanceID, path)
}

func (m *Provider) openInstance(ctx context.Context, instanceID string) (*sqlitevault.Unsafe, error) {
	path, err := m.resolveInstancePath(instanceID)
	if err != nil {
		return nil, err
	}
	return openVault(ctx, instanceID, path)
}

func (m *Provider) resolveInstancePath(instanceID string) (string, error) {
	path, err := m.instancePath(instanceID)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "", ErrInstanceNotFound
	} else if err != nil {
		return "", err
	}
	return path, nil
}

func (m *Provider) instancePath(instanceID string) (string, error) {
	if instanceID == "" {
		return "", ErrInstanceIDMissing
	}
	filename := base64.RawURLEncoding.EncodeToString([]byte(instanceID))
	return filepath.Join(m.dir, filename+".db"), nil
}

func openVault(ctx context.Context, instanceID, path string) (*sqlitevault.Unsafe, error) {
	return sqlitevault.NewUnsafe(ctx, instanceID, sqlitevault.FileSource(path))
}

func keySecretID(keyID string) string {
	return "key:" + keyID
}

func authSecretID(keyID string) string {
	return "auth:" + keyID
}
