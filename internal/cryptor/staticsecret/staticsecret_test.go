package staticsecret_test

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/cryptor/staticsecret"
	"github.com/openkcm/krypton/internal/securemem"
)

func TestStaticSecret_New(t *testing.T) {
	// given
	secretWithInvalidLen, err := securemem.NewData("key", 16)
	require.NoError(t, err)
	t.Cleanup(func() { _ = secretWithInvalidLen.Destroy() })

	tts := []struct {
		name    string
		nameArg string
		keyArg  *securemem.Data
		wantErr bool
	}{
		{
			name:    "should not return error for valid name and key",
			nameArg: "test-static-secret",
			keyArg:  newSecretKey(t),
			wantErr: false,
		},
		{
			name:    "should return error for empty name",
			nameArg: "",
			keyArg:  newSecretKey(t),
			wantErr: true,
		},
		{
			name:    "should return error for nil secret",
			nameArg: "test-static-secret",
			keyArg:  nil,
			wantErr: true,
		},
		{
			name:    "should return error for empty secret",
			nameArg: "test-static-secret",
			keyArg:  &securemem.Data{},
			wantErr: true,
		},
		{
			name:    "should return error for invalid secret size",
			nameArg: "test-static-secret",
			keyArg:  secretWithInvalidLen,
			wantErr: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			subj, err := staticsecret.New(tt.nameArg, tt.keyArg)

			// then
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, subj)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, subj)
			}
		})
	}
}

func TestStaticSecret_Seal(t *testing.T) {
	// given
	ctx := t.Context()

	subj, err := staticsecret.New("test-static-secret", newSecretKey(t))
	require.NoError(t, err)

	t.Run("should fail if plaintext is nil", func(t *testing.T) {
		// given
		req := cryptor.SealRequest{
			Plaintext: nil,
		}

		// when
		resp, err := subj.Seal(ctx, req)

		// then
		assert.Error(t, err)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should succeed with valid plaintext", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.SealRequest{
			Plaintext: plainText,
		}

		// when
		resp, err := subj.Seal(ctx, req)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp.Ciphertext)
		t.Cleanup(func() { _ = resp.Ciphertext.Destroy() })
	})

	t.Run("should fail to seal if plaintext data is destroyed", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.SealRequest{
			Plaintext: plainText,
		}

		// destroy plaintext before sealing
		require.NoError(t, plainText.Destroy())

		// when
		resp, err := subj.Seal(ctx, req)

		// then
		assert.Error(t, err)
		assert.Equal(t, cryptor.SealResponse{}, resp)
	})

	t.Run("should generate different ciphertext for same plaintext and key", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.SealRequest{
			Plaintext: plainText,
		}

		// when
		resp1, err := subj.Seal(ctx, req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp1.Ciphertext.Destroy() })

		resp2, err := subj.Seal(ctx, req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp2.Ciphertext.Destroy() })

		// then
		assert.NotEqual(t, resp1.Ciphertext.SecureBytes(), resp2.Ciphertext.SecureBytes())
	})

	t.Run("should not destroy plaintext after sealing", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.SealRequest{
			Plaintext: plainText,
		}

		// when
		resp, err := subj.Seal(ctx, req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Ciphertext.Destroy() })

		// then
		assert.NotNil(t, plainText.SecureBytes())
	})
}

func TestStaticSecret_Unseal(t *testing.T) {
	// given
	ctx := t.Context()
	subj, err := staticsecret.New("test-static-secret", newSecretKey(t))
	require.NoError(t, err)

	t.Run("should fail if ciphertext is nil", func(t *testing.T) {
		// given
		req := cryptor.UnsealRequest{
			Ciphertext: nil,
		}

		// when
		resp, err := subj.Unseal(ctx, req)

		// then
		assert.Error(t, err)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})

	t.Run("should fail to unseal if ciphertext data is destroyed", func(t *testing.T) {
		// given
		cipherText := newSecureMemData(t, []byte("ciphertext"))

		req := cryptor.UnsealRequest{
			Ciphertext: cipherText,
		}

		// destroy ciphertext before unsealing
		require.NoError(t, cipherText.Destroy())

		// when
		resp, err := subj.Unseal(ctx, req)

		// then
		assert.Error(t, err)
		assert.Equal(t, cryptor.UnsealResponse{}, resp)
	})
}

func TestStaticSecret_SealUnseal(t *testing.T) {
	// given
	ctx := t.Context()

	subj, err := staticsecret.New("test-static-secret", newSecretKey(t))
	require.NoError(t, err)

	t.Run("should seal and unseal plaintext successfully", func(t *testing.T) {
		// given
		text := []byte("hello, secure world!")
		plainText := newSecureMemData(t, text)

		// when
		sealResp, err := subj.Seal(ctx, cryptor.SealRequest{
			Plaintext: plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealResp.Ciphertext.Destroy() })

		// ciphertext must differ from plaintext
		assert.NotEqual(t, text, []byte(sealResp.Ciphertext.SecureBytes()))

		// when
		unsealResp, err := subj.Unseal(ctx, cryptor.UnsealRequest{
			Ciphertext: sealResp.Ciphertext,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = unsealResp.Plaintext.Destroy() })

		// recovered plaintext must match original
		assert.Equal(t, text, []byte(unsealResp.Plaintext.SecureBytes()))
	})

	t.Run("should seal and unseal with AAD successfully", func(t *testing.T) {
		// given
		text := []byte("authenticated payload")
		plainText := newSecureMemData(t, text)
		aad := []byte("context-binding-data")

		// when
		sealResp, err := subj.Seal(ctx, cryptor.SealRequest{
			Plaintext: plainText,
			AAD:       aad,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealResp.Ciphertext.Destroy() })

		// when
		unsealResp, err := subj.Unseal(ctx, cryptor.UnsealRequest{
			Ciphertext: sealResp.Ciphertext,
			AAD:        aad,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = unsealResp.Plaintext.Destroy() })

		assert.Equal(t, text, []byte(unsealResp.Plaintext.SecureBytes()))
	})

	t.Run("should fail to unseal with wrong AAD", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("secret"))

		// when
		sealResp, err := subj.Seal(ctx, cryptor.SealRequest{
			Plaintext: plainText,
			AAD:       []byte("correct-aad"),
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealResp.Ciphertext.Destroy() })

		// when
		unsealResp, err := subj.Unseal(ctx, cryptor.UnsealRequest{
			Ciphertext: sealResp.Ciphertext,
			AAD:        []byte("wrong-aad"),
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, cryptor.UnsealResponse{}, unsealResp)
	})

	t.Run("should fail to unseal with wrong key", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("secret"))

		// when
		sealResp, err := subj.Seal(ctx, cryptor.SealRequest{
			Plaintext: plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealResp.Ciphertext.Destroy() })

		// when
		subj1, err := staticsecret.New("test-static-secret", newSecretKey(t))
		require.NoError(t, err)

		unsealResp, err := subj1.Unseal(ctx, cryptor.UnsealRequest{
			Ciphertext: sealResp.Ciphertext,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, cryptor.UnsealResponse{}, unsealResp)
	})

	t.Run("should fail to unseal tampered ciphertext", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("do not tamper"))

		// when
		sealResp, err := subj.Seal(ctx, cryptor.SealRequest{
			Plaintext: plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealResp.Ciphertext.Destroy() })

		// copy ciphertext into writable secure memory and flip a byte
		ct := sealResp.Ciphertext.SecureBytes()
		tampered, err := securemem.NewData("tampered", len(ct))
		require.NoError(t, err)

		t.Cleanup(func() { _ = tampered.Destroy() })

		copy(tampered.SecureBytes(), ct)
		tampered.SecureBytes()[len(ct)-1] ^= 0xFF

		// when
		unsealResp, err := subj.Unseal(ctx, cryptor.UnsealRequest{
			Ciphertext: tampered,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, cryptor.UnsealResponse{}, unsealResp)
	})

	t.Run("should fail to unseal if ciphertext is too short to contain nonce and tag", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("short cipher"))

		// when
		sealResp, err := subj.Seal(ctx, cryptor.SealRequest{
			Plaintext: plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealResp.Ciphertext.Destroy() })

		// create a truncated ciphertext that is too short to contain nonce and tag
		ct := sealResp.Ciphertext.SecureBytes()
		truncated, err := securemem.NewData("truncated", 8) // too short for nonce+tag
		require.NoError(t, err)

		t.Cleanup(func() { _ = truncated.Destroy() })
		copy(truncated.SecureBytes(), ct[:8])

		// when
		unsealResp, err := subj.Unseal(ctx, cryptor.UnsealRequest{
			Ciphertext: truncated,
		})

		// then
		assert.Error(t, err)
		assert.Equal(t, cryptor.UnsealResponse{}, unsealResp)
	})

	t.Run("should not destroy ciphertext after unsealing", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		// when
		sealResp, err := subj.Seal(ctx, cryptor.SealRequest{
			Plaintext: plainText,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = sealResp.Ciphertext.Destroy() })

		unsealResp, err := subj.Unseal(ctx, cryptor.UnsealRequest{
			Ciphertext: sealResp.Ciphertext,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = unsealResp.Plaintext.Destroy() })

		// then
		assert.NotNil(t, sealResp.Ciphertext.SecureBytes())
	})
}

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
