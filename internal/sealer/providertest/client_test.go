package providertest_test

import (
	"testing"
	"uuid"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/providertest"
	"github.com/openkcm/krypton/internal/securemem"
)

func TestClientValidation(t *testing.T) {
	enableProvider(t)

	tests := []struct {
		name    string
		config  providertest.Config
		auth    providertest.Auth
		wantErr error
	}{
		{name: "instance ID", auth: providertest.Auth{Token: "token"}, wantErr: providertest.ErrInstanceIDMissing},
		{name: "access token", config: providertest.Config{InstanceID: "instance"}, wantErr: providertest.ErrAccessTokenMissing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := providertest.NewClient(tt.config, tt.auth)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestClientRoundTrip(t *testing.T) {
	provider, instanceID := newProviderInstance(t)
	ctx := t.Context()
	keyID := uuid.New().String() + ":1"
	require.NoError(t, provider.UpsertKey(ctx, instanceID, keyID))
	require.NoError(t, provider.UpsertKeyAuth(ctx, instanceID, keyID, "access-token"))

	client := newClient(t, instanceID, "access-token")
	sealed, err := client.Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "secret"),
		AAD:       []byte("aad"),
		Metadata:  metadata(keyID),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Ciphertext.Destroy() })

	unsealed, err := client.Unseal(ctx, sealer.UnsealRequest{
		Ciphertext: sealed.Ciphertext,
		AAD:        []byte("aad"),
		Metadata:   metadata(keyID),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = unsealed.Plaintext.Destroy() })
	assert.Equal(t, "secret", string(unsealed.Plaintext.SecureBytes()))
}

func TestClientAuthIsKeyBound(t *testing.T) {
	provider, instanceID := newProviderInstance(t)
	ctx := t.Context()

	for keyID, token := range map[string]providertest.AccessToken{
		"first":  "first-token",
		"second": "second-token",
	} {
		require.NoError(t, provider.UpsertKey(ctx, instanceID, keyID))
		require.NoError(t, provider.UpsertKeyAuth(ctx, instanceID, keyID, token))
	}

	client := newClient(t, instanceID, "first-token")
	_, err := client.Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "secret"),
		Metadata:  metadata("second"),
	})
	assert.ErrorIs(t, err, providertest.ErrUnauthorized)
}

func TestClientErrors(t *testing.T) {
	provider, instanceID := newProviderInstance(t)
	ctx := t.Context()
	require.NoError(t, provider.UpsertKey(ctx, instanceID, "key"))
	require.NoError(t, provider.UpsertKeyAuth(ctx, instanceID, "key", "token"))

	t.Run("missing key ID", func(t *testing.T) {
		client := newClient(t, instanceID, "token")
		_, err := client.Seal(ctx, sealer.SealRequest{Plaintext: newData(t, "secret")})
		assert.ErrorIs(t, err, providertest.ErrKeyIDMissing)
	})

	t.Run("wrong token", func(t *testing.T) {
		client := newClient(t, instanceID, "wrong")
		_, err := client.Seal(ctx, sealer.SealRequest{
			Plaintext: newData(t, "secret"),
			Metadata:  metadata("key"),
		})
		assert.ErrorIs(t, err, providertest.ErrUnauthorized)
	})

	t.Run("missing auth", func(t *testing.T) {
		require.NoError(t, provider.UpsertKey(ctx, instanceID, "no-auth"))
		client := newClient(t, instanceID, "token")
		_, err := client.Seal(ctx, sealer.SealRequest{
			Plaintext: newData(t, "secret"),
			Metadata:  metadata("no-auth"),
		})
		assert.ErrorIs(t, err, providertest.ErrAuthNotFound)
	})

	t.Run("missing key", func(t *testing.T) {
		require.NoError(t, provider.UpsertKeyAuth(ctx, instanceID, "no-key", "token"))
		client := newClient(t, instanceID, "token")
		_, err := client.Seal(ctx, sealer.SealRequest{
			Plaintext: newData(t, "secret"),
			Metadata:  metadata("no-key"),
		})
		assert.ErrorIs(t, err, providertest.ErrKeyNotFound)
	})
}

func TestClientObservesUpserts(t *testing.T) {
	provider, instanceID := newProviderInstance(t)
	ctx := t.Context()
	keyID := "key"
	require.NoError(t, provider.UpsertKey(ctx, instanceID, keyID))
	require.NoError(t, provider.UpsertKeyAuth(ctx, instanceID, keyID, "initial"))

	initialClient := newClient(t, instanceID, "initial")
	sealed, err := initialClient.Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "secret"),
		Metadata:  metadata(keyID),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Ciphertext.Destroy() })

	require.NoError(t, provider.UpsertKeyAuth(ctx, instanceID, keyID, "replacement"))
	_, err = initialClient.Unseal(ctx, sealer.UnsealRequest{Ciphertext: sealed.Ciphertext, Metadata: metadata(keyID)})
	assert.ErrorIs(t, err, providertest.ErrUnauthorized)

	replacementClient := newClient(t, instanceID, "replacement")
	require.NoError(t, provider.UpsertKey(ctx, instanceID, keyID))
	_, err = replacementClient.Unseal(ctx, sealer.UnsealRequest{Ciphertext: sealed.Ciphertext, Metadata: metadata(keyID)})
	assert.Error(t, err)
}

func TestClientInstancesAreIsolated(t *testing.T) {
	enableProvider(t)
	provider, err := providertest.New()
	require.NoError(t, err)
	ctx := t.Context()

	keyID := "shared"
	first, second := "instance-a", "instance-b"

	for _, instanceID := range []string{first, second} {
		require.NoError(t, provider.UpsertInstance(ctx, instanceID))
		require.NoError(t, provider.UpsertKey(ctx, instanceID, keyID))
		require.NoError(t, provider.UpsertKeyAuth(ctx, instanceID, keyID, "token"))
	}

	sealed, err := newClient(t, first, "token").Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "secret"),
		Metadata:  metadata(keyID),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Ciphertext.Destroy() })

	_, err = newClient(t, second, "token").Unseal(ctx, sealer.UnsealRequest{
		Ciphertext: sealed.Ciphertext,
		Metadata:   metadata(keyID),
	})
	assert.Error(t, err)
}

func newProviderInstance(t *testing.T) (*providertest.Provider, string) {
	t.Helper()
	enableProvider(t)
	provider, err := providertest.New()
	require.NoError(t, err)
	instanceID := "../provider/instance"
	require.NoError(t, provider.UpsertInstance(t.Context(), instanceID))
	return provider, instanceID
}

func newClient(t *testing.T, instanceID string, token providertest.AccessToken) *providertest.Client {
	t.Helper()
	client, err := providertest.NewClient(
		providertest.Config{InstanceID: instanceID},
		providertest.Auth{Token: token},
	)
	require.NoError(t, err)
	return client
}

func newData(t *testing.T, value string) *securemem.Data {
	t.Helper()
	data, err := securemem.NewData("test", len(value))
	require.NoError(t, err)
	copy(data.SecureBytes(), value)
	t.Cleanup(func() { _ = data.Destroy() })
	return data
}

func metadata(keyID string) map[string]string {
	return map[string]string{
		sealer.ProviderKeyMetadataKey(providertest.TypeProviderTest): keyID,
	}
}
