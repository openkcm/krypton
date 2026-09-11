package securemem_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/stats"

	"github.com/openkcm/krypton/internal/securemem"
)

func TestRPCHandler(t *testing.T) {
	t.Run("should destroy vault after successful RPC", func(t *testing.T) {
		// given
		subj := securemem.NewRPCHandler()
		ctx := subj.TagRPC(context.Background(), &stats.RPCTagInfo{})

		vault, ok := securemem.VaultFromContext(ctx)
		require.True(t, ok, "vault should be in context from TagRPC")

		// reserve some secure memory and import it into the vault
		b, err := securemem.NewData("test-secret", 6)
		require.NoError(t, err)
		copy(b.SecureBytes(), []byte("secret"))

		err = vault.Import("test-secret", b)
		require.NoError(t, err)

		// when — simulate stats.End (successful RPC)
		subj.HandleRPC(ctx, &stats.End{})

		// then — the vault data should be destroyed by HandleRPC
		assert.Nil(t, b.SecureBytes(), "secure memory should be zeroed after RPC completes")

		_, ok = vault.Get("test-secret")
		assert.False(t, ok, "vault entry should be removed after destroy")
	})

	t.Run("should destroy vault after failed RPC", func(t *testing.T) {
		// given
		subj := securemem.NewRPCHandler()
		ctx := subj.TagRPC(context.Background(), &stats.RPCTagInfo{})

		vault, ok := securemem.VaultFromContext(ctx)
		require.True(t, ok)

		b, err := securemem.NewData("test-secret", 6)
		require.NoError(t, err)
		copy(b.SecureBytes(), []byte("secret"))

		err = vault.Import("test-secret", b)
		require.NoError(t, err)

		// when — simulate stats.End with an error (failed RPC)
		subj.HandleRPC(ctx, &stats.End{Error: assert.AnError})

		// then
		assert.Nil(t, b.SecureBytes(), "secure memory should be zeroed even when RPC fails")
	})

	t.Run("should provide vault to handler via TagRPC", func(t *testing.T) {
		// given
		subj := securemem.NewRPCHandler()

		// when
		ctx := subj.TagRPC(context.Background(), &stats.RPCTagInfo{})

		// then
		_, ok := securemem.VaultFromContext(ctx)
		assert.True(t, ok, "TagRPC should have created a vault in the context")
	})

	t.Run("should not destroy vault on non-End events", func(t *testing.T) {
		// given
		subj := securemem.NewRPCHandler()
		ctx := subj.TagRPC(context.Background(), &stats.RPCTagInfo{})

		vault, ok := securemem.VaultFromContext(ctx)
		require.True(t, ok)

		b, err := securemem.NewData("test-secret", 6)
		require.NoError(t, err)
		copy(b.SecureBytes(), []byte("secret"))

		err = vault.Import("test-secret", b)
		require.NoError(t, err)

		// when — simulate a non-End event
		subj.HandleRPC(ctx, &stats.Begin{})

		// then — vault should remain intact
		assert.NotNil(t, b.SecureBytes(), "secure memory should not be zeroed on Begin event")

		_, ok = vault.Get("test-secret")
		assert.True(t, ok, "vault entry should still exist after non-End event")
	})
}
