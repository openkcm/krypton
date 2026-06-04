package cryptor_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/securemem"
)

// newSecretKey allocate a 32-byte AES key in secure memory
func newSecretKey(t *testing.T) *securemem.Data {
	t.Helper()

	key, err := securemem.NewData("test-key", 32)
	require.NoError(t, err)

	_, err = rand.Read(key.SecureBytes())
	require.NoError(t, err)

	t.Cleanup(func() { _ = key.Destroy() })

	return key
}

// newSecureMemData allocate in secure memory
func newSecureMemData(t *testing.T, content []byte) *securemem.Data {
	t.Helper()

	pt, err := securemem.NewData("test-plaintext", len(content))
	require.NoError(t, err)

	copy(pt.SecureBytes(), content)

	t.Cleanup(func() { _ = pt.Destroy() })

	return pt
}
