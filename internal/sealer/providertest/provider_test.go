package providertest_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/sealer/providertest"
)

func TestNewValidatesEnvironment(t *testing.T) {
	t.Run("confirmation", func(t *testing.T) {
		t.Setenv(providertest.EnableEnv, "NO")
		t.Setenv(providertest.DirectoryEnv, t.TempDir())

		_, err := providertest.New()
		assert.Error(t, err)
	})

	t.Run("storage directory", func(t *testing.T) {
		t.Setenv(providertest.EnableEnv, providertest.EnableAck)
		t.Setenv(providertest.DirectoryEnv, "")

		_, err := providertest.New()
		assert.ErrorIs(t, err, providertest.ErrStorageDirectoryMissing)
	})
}

func TestProviderRequiresExistingInstance(t *testing.T) {
	enableProvider(t)
	provider, err := providertest.New()
	require.NoError(t, err)
	ctx := t.Context()

	err = provider.UpsertKey(ctx, "missing", "key")
	assert.ErrorIs(t, err, providertest.ErrInstanceNotFound)

	err = provider.UpsertKeyAuth(ctx, "missing", "key", "token")
	assert.ErrorIs(t, err, providertest.ErrInstanceNotFound)

	err = provider.DeleteInstance("missing")
	assert.ErrorIs(t, err, providertest.ErrInstanceNotFound)
}

func TestProviderRejectsEmptyValues(t *testing.T) {
	enableProvider(t)
	provider, err := providertest.New()
	require.NoError(t, err)
	ctx := t.Context()

	tests := []struct {
		name    string
		call    func() error
		wantErr error
	}{
		{"instance: empty ID", func() error {
			return provider.UpsertInstance(ctx, "")
		}, providertest.ErrInstanceIDMissing},

		{"key: empty key", func() error {
			return provider.UpsertKey(ctx, "instance", "")
		}, providertest.ErrKeyIDMissing},
		{"key: empty instance+key", func() error {
			return provider.UpsertKey(ctx, "", "")
		}, providertest.ErrKeyIDMissing},
		{"key: empty instance only", func() error {
			return provider.UpsertKey(ctx, "", "key")
		}, providertest.ErrInstanceIDMissing},

		{"auth: empty key", func() error {
			return provider.UpsertKeyAuth(ctx, "instance", "", "token")
		}, providertest.ErrKeyIDMissing},
		{"auth: empty token", func() error {
			return provider.UpsertKeyAuth(ctx, "instance", "key", "")
		}, providertest.ErrAccessTokenMissing},
		{"auth: empty instance only", func() error {
			return provider.UpsertKeyAuth(ctx, "", "key", "token")
		}, providertest.ErrInstanceIDMissing},
		{"auth: all empty", func() error {
			return provider.UpsertKeyAuth(ctx, "", "", "")
		}, providertest.ErrKeyIDMissing},

		{"delete: empty ID", func() error {
			return provider.DeleteInstance("")
		}, providertest.ErrInstanceIDMissing},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(), tt.wantErr)
		})
	}
}

func TestInstanceLifecycle(t *testing.T) {
	enableProvider(t)
	provider, err := providertest.New()
	require.NoError(t, err)
	ctx := t.Context()
	instanceID := "../provider/instance"

	require.NoError(t, provider.UpsertInstance(ctx, instanceID))
	require.NoError(t, provider.UpsertKey(ctx, instanceID, "key"))
	require.NoError(t, provider.UpsertKeyAuth(ctx, instanceID, "key", "token"))

	reopened, err := providertest.New()
	require.NoError(t, err)
	require.NoError(t, reopened.UpsertKeyAuth(ctx, instanceID, "key", "replacement"))

	require.NoError(t, provider.DeleteInstance(instanceID))
	err = reopened.UpsertKey(ctx, instanceID, "key")
	assert.ErrorIs(t, err, providertest.ErrInstanceNotFound)
}

func enableProvider(t *testing.T) {
	t.Helper()
	t.Setenv(providertest.EnableEnv, providertest.EnableAck)
	t.Setenv(providertest.DirectoryEnv, t.TempDir())
}
