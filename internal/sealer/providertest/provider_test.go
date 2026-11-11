package providertest_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/sealer"
	"github.com/openkcm/krypton/internal/sealer/providertest"
	"github.com/openkcm/krypton/internal/securemem"
)

func TestKeyRef(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    providertest.KeyRef
		wantErr error
	}{
		{
			name:  "valid reference",
			value: "providertest:key-id:2",
			want: providertest.KeyRef{
				TenantID: "providertest",
				KeyID:    "key-id",
				Version:  2,
			},
		},
		{
			name:    "missing reference",
			wantErr: providertest.ErrKeyRefMissing,
		},
		{
			name:    "different tenant",
			value:   "other:key-id:1",
			wantErr: providertest.ErrInvalidKeyRef,
		},
		{
			name:    "missing key id",
			value:   "providertest::1",
			wantErr: providertest.ErrInvalidKeyRef,
		},
		{
			name:    "missing version",
			value:   "providertest:key-id",
			wantErr: providertest.ErrInvalidKeyRef,
		},
		{
			name:    "invalid version",
			value:   "providertest:key-id:invalid",
			wantErr: providertest.ErrInvalidKeyRef,
		},
		{
			name:    "zero version",
			value:   "providertest:key-id:0",
			wantErr: providertest.ErrInvalidKeyRef,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := providertest.ParseKeyRef(tt.value)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, providertest.KeyRef{}, got)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.value, got.String())
		})
	}
}

func TestClient(t *testing.T) {
	ctx := t.Context()

	provider, err := providertest.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })

	auth, keyRef, err := provider.CreateKey(ctx)
	require.NoError(t, err)

	client, err := providertest.NewClient(ctx, auth)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	t.Run("missing auth", func(t *testing.T) {
		_, err := providertest.NewClient(ctx, providertest.Auth{})

		assert.ErrorIs(t, err, providertest.ErrAccessTokenMissing)
	})

	t.Run("missing key reference", func(t *testing.T) {
		_, err := client.Seal(ctx, sealer.SealRequest{
			Plaintext: newData(t, "secret"),
		})

		assert.ErrorIs(t, err, providertest.ErrKeyRefMissing)
	})

	t.Run("invalid key reference", func(t *testing.T) {
		_, err := client.Seal(ctx, sealer.SealRequest{
			Plaintext: newData(t, "secret"),
			Metadata: map[string]string{
				sealer.ProviderKeyMetadataKey(providertest.TypeProviderTest): "invalid",
			},
		})

		assert.ErrorIs(t, err, providertest.ErrInvalidKeyRef)
	})

	invalidTokens := []struct {
		name  string
		token providertest.AccessToken
	}{
		{name: "malformed", token: "%"},
		{name: "wrong length", token: providertest.AccessToken(base64.RawURLEncoding.EncodeToString([]byte{0}))},
		{name: "incorrect", token: providertest.AccessToken(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))},
	}
	for _, tt := range invalidTokens {
		t.Run(tt.name+" token", func(t *testing.T) {
			invalidClient, err := providertest.NewClient(ctx, providertest.Auth{Token: tt.token})
			require.NoError(t, err)
			t.Cleanup(func() { _ = invalidClient.Close() })

			_, err = invalidClient.Seal(ctx, sealer.SealRequest{
				Plaintext: newData(t, "secret"),
				Metadata:  metadata(keyRef),
			})

			assert.ErrorIs(t, err, providertest.ErrUnauthorized)
		})
	}
}

func TestRoundTrip(t *testing.T) {
	ctx := t.Context()

	provider, err := providertest.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })

	auth, keyRef, err := provider.CreateKey(ctx)
	require.NoError(t, err)

	client, err := providertest.NewClient(ctx, auth)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	sealed, err := client.Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "secret"),
		AAD:       []byte("aad"),
		Metadata:  metadata(keyRef),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Ciphertext.Destroy() })

	unsealed, err := client.Unseal(ctx, sealer.UnsealRequest{
		Ciphertext: sealed.Ciphertext,
		AAD:        []byte("aad"),
		Metadata:   metadata(keyRef),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = unsealed.Plaintext.Destroy() })

	assert.Equal(t, "secret", string(unsealed.Plaintext.SecureBytes()))
}

func TestKeyVersions(t *testing.T) {
	ctx := t.Context()

	provider, err := providertest.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })

	_, first, err := provider.CreateKey(ctx)
	require.NoError(t, err)
	_, second, err := provider.CreateKey(ctx)
	require.NoError(t, err)

	tests := []struct {
		name string
		ref  providertest.KeyRef
	}{
		{name: "first key", ref: first},
		{name: "second key", ref: second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := provider.RotateKey(ctx, tt.ref.KeyID)

			require.NoError(t, err)
			assert.Equal(t, tt.ref.TenantID, got.TenantID)
			assert.Equal(t, tt.ref.KeyID, got.KeyID)
			assert.Equal(t, 2, got.Version)
		})
	}
}

func TestKeyRotation(t *testing.T) {
	ctx := t.Context()

	provider, err := providertest.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })

	t.Run("unknown key", func(t *testing.T) {
		_, err := provider.RotateKey(ctx, "unknown")

		assert.ErrorIs(t, err, providertest.ErrKeyNotFound)
	})

	auth, firstRef, err := provider.CreateKey(ctx)
	require.NoError(t, err)

	client, err := providertest.NewClient(ctx, auth)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	first, err := client.Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "first"),
		AAD:       []byte("aad"),
		Metadata:  metadata(firstRef),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Ciphertext.Destroy() })

	secondRef, err := provider.RotateKey(ctx, firstRef.KeyID)
	require.NoError(t, err)

	second, err := client.Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "second"),
		AAD:       []byte("aad"),
		Metadata:  metadata(secondRef),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Ciphertext.Destroy() })

	_, err = client.Unseal(ctx, sealer.UnsealRequest{
		Ciphertext: first.Ciphertext,
		AAD:        []byte("aad"),
		Metadata:   metadata(secondRef),
	})
	assert.Error(t, err)

	tests := []struct {
		name       string
		ref        providertest.KeyRef
		ciphertext *securemem.Data
		want       string
	}{
		{name: "first version", ref: firstRef, ciphertext: first.Ciphertext, want: "first"},
		{name: "second version", ref: secondRef, ciphertext: second.Ciphertext, want: "second"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unsealed, err := client.Unseal(ctx, sealer.UnsealRequest{
				Ciphertext: tt.ciphertext,
				AAD:        []byte("aad"),
				Metadata:   metadata(tt.ref),
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = unsealed.Plaintext.Destroy() })

			assert.Equal(t, tt.want, string(unsealed.Plaintext.SecureBytes()))
		})
	}
}

func TestAuthRotation(t *testing.T) {
	ctx := t.Context()

	provider, err := providertest.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })

	t.Run("unknown auth", func(t *testing.T) {
		_, err := provider.RotateAuth(ctx, "unknown")

		assert.ErrorIs(t, err, providertest.ErrAuthNotFound)
	})

	initialAuth, keyRef, err := provider.CreateKey(ctx)
	require.NoError(t, err)

	initialClient, err := providertest.NewClient(ctx, initialAuth)
	require.NoError(t, err)
	t.Cleanup(func() { _ = initialClient.Close() })

	sealed, err := initialClient.Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "secret"),
		Metadata:  metadata(keyRef),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sealed.Ciphertext.Destroy() })

	rotatedAuth, err := provider.RotateAuth(ctx, keyRef.KeyID)
	require.NoError(t, err)

	_, err = initialClient.Unseal(ctx, sealer.UnsealRequest{
		Ciphertext: sealed.Ciphertext,
		Metadata:   metadata(keyRef),
	})
	assert.ErrorIs(t, err, providertest.ErrUnauthorized)

	rotatedClient, err := providertest.NewClient(ctx, rotatedAuth)
	require.NoError(t, err)
	t.Cleanup(func() { _ = rotatedClient.Close() })

	unsealed, err := rotatedClient.Unseal(ctx, sealer.UnsealRequest{
		Ciphertext: sealed.Ciphertext,
		Metadata:   metadata(keyRef),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = unsealed.Plaintext.Destroy() })

	assert.Equal(t, "secret", string(unsealed.Plaintext.SecureBytes()))
}

func TestDestroyKey(t *testing.T) {
	ctx := t.Context()

	provider, err := providertest.New(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = provider.Close() })

	auth, keyRef, err := provider.CreateKey(ctx)
	require.NoError(t, err)

	client, err := providertest.NewClient(ctx, auth)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	require.NoError(t, provider.DestroyKey(ctx, keyRef.KeyID))

	_, err = client.Seal(ctx, sealer.SealRequest{
		Plaintext: newData(t, "secret"),
		Metadata:  metadata(keyRef),
	})
	assert.ErrorIs(t, err, providertest.ErrAuthNotFound)

	_, err = provider.RotateAuth(ctx, keyRef.KeyID)
	assert.ErrorIs(t, err, providertest.ErrAuthNotFound)

	_, err = provider.RotateKey(ctx, keyRef.KeyID)
	assert.ErrorIs(t, err, providertest.ErrKeyNotFound)

	err = provider.DestroyKey(ctx, keyRef.KeyID)
	assert.ErrorIs(t, err, providertest.ErrKeyNotFound)
}

func newData(t *testing.T, value string) *securemem.Data {
	t.Helper()

	data, err := securemem.NewData("test", len(value))
	require.NoError(t, err)
	copy(data.SecureBytes(), value)
	t.Cleanup(func() { _ = data.Destroy() })

	return data
}

func metadata(ref providertest.KeyRef) map[string]string {
	return map[string]string{
		sealer.ProviderKeyMetadataKey(providertest.TypeProviderTest): ref.String(),
	}
}
