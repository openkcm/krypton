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

func TestStaticSecret_Encrypt(t *testing.T) {
	// given
	ctx := t.Context()

	subj, err := staticsecret.New("test-static-secret", newSecretKey(t))
	require.NoError(t, err)

	t.Run("should fail if encrypt request validation fails", func(t *testing.T) {
		// given
		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  nil, // missing plaintext
		}

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail if encrypt request contains a secret", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
			Secret: &cryptor.Secret{
				Data:      newSecretKey(t),
				Algorithm: cryptor.KeyAlgorithmAES256,
			},
		}

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail if encrypt request contains empty secret", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
			Secret:     &cryptor.Secret{},
		}

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should not fail if encrypt request is missing secret", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
			Secret:     nil, // missing secret
		}

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		t.Cleanup(func() { _ = resp.Ciphertext.Destroy() })
	})

	t.Run("should fail to encrypt if plaintext data is destroyed", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
		}

		// destroy plaintext before encryption
		require.NoError(t, plainText.Destroy())

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should generate different ciphertext for same plaintext and key", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
		}

		// when
		resp1, err := subj.Encrypt(ctx, req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp1.Ciphertext.Destroy() })

		resp2, err := subj.Encrypt(ctx, req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp2.Ciphertext.Destroy() })

		// then
		assert.NotEqual(t, resp1.Ciphertext.SecureBytes(), resp2.Ciphertext.SecureBytes())
	})

	t.Run("should not destroy plaintext after encryption", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
		}

		// when
		resp, err := subj.Encrypt(ctx, req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Ciphertext.Destroy() })

		// then
		assert.NotNil(t, plainText.SecureBytes())
	})
}

func TestStaticSecret_Decrypt(t *testing.T) {
	// given
	ctx := t.Context()
	subj, err := staticsecret.New("test-static-secret", newSecretKey(t))
	require.NoError(t, err)

	t.Run("should fail if decrypt request validation fails", func(t *testing.T) {
		// given
		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: nil, // missing ciphertext
		}

		// when
		resp, err := subj.Decrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail if decrypt request contains a secret", func(t *testing.T) {
		// given
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  newSecureMemData(t, []byte("ciphertext")),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
			Secret: &cryptor.Secret{
				Data:      newSecretKey(t),
				Algorithm: cryptor.KeyAlgorithmAES256,
			},
		}

		// when
		resp, err := subj.Decrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail if decrypt request contains empty secret", func(t *testing.T) {
		// given
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  newSecureMemData(t, []byte("ciphertext")),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
			Secret:     &cryptor.Secret{},
		}

		// when
		resp, err := subj.Decrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should not fail if decrypt request is missing secret", func(t *testing.T) {
		// given
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  newSecureMemData(t, []byte("ciphertext")),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
			Secret:     nil, // missing secret
		}

		// when
		resp, err := subj.Decrypt(ctx, req)

		// then
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		t.Cleanup(func() { _ = resp.Plaintext.Destroy() })
	})

	t.Run("should fail to decrypt if ciphertext data is destroyed", func(t *testing.T) {
		// given
		cipherText := newSecureMemData(t, []byte("ciphertext"))

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: cipherText,
		}

		// destroy ciphertext before decryption
		require.NoError(t, cipherText.Destroy())

		// when
		resp, err := subj.Decrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})
}

func TestStaticSecret_EncryptDecrypt(t *testing.T) {
	// given
	ctx := t.Context()

	subj, err := staticsecret.New("test-static-secret", newSecretKey(t))
	require.NoError(t, err)

	t.Run("should encrypt and decrypt plaintext successfully", func(t *testing.T) {
		// given
		text := []byte("hello, secure world!")
		plainText := newSecureMemData(t, text)

		// when
		// encrypt
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		// ciphertext must differ from plaintext
		assert.NotEqual(t, text, []byte(encResp.Ciphertext.SecureBytes()))

		// when
		// decrypt
		decResp, err := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = decResp.Plaintext.Destroy() })

		// recovered plaintext must match original
		assert.Equal(t, text, []byte(decResp.Plaintext.SecureBytes()))
	})

	t.Run("should encrypt and decrypt with AAD successfully", func(t *testing.T) {
		// given
		text := []byte("authenticated payload")
		plainText := newSecureMemData(t, text)
		aad := []byte("context-binding-data")

		// when
		// encrypt with AAD
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
			AAD:        aad,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		// when
		// decrypt with same AAD succeeds
		decResp, err := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
			AAD:        aad,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = decResp.Plaintext.Destroy() })

		assert.Equal(t, text, []byte(decResp.Plaintext.SecureBytes()))
	})

	t.Run("should fail to decrypt with wrong AAD", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("secret"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
			AAD:        []byte("correct-aad"),
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		// when
		// decrypt with wrong AAD must fail
		decResp, err := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
			AAD:        []byte("wrong-aad"),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should fail to decrypt with wrong key", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("secret"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		// when
		// decrypt with different staticsecret must fail
		subj1, err := staticsecret.New("test-static-secret", newSecretKey(t))
		require.NoError(t, err)

		decResp, err := subj1.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should fail to decrypt tampered ciphertext", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("do not tamper"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		// copy ciphertext into writable secure memory and flip a byte
		ct := encResp.Ciphertext.SecureBytes()
		tampered, err := securemem.NewData("tampered", len(ct))
		require.NoError(t, err)

		t.Cleanup(func() { _ = tampered.Destroy() })

		copy(tampered.SecureBytes(), ct)
		tampered.SecureBytes()[len(ct)-1] ^= 0xFF

		// when
		decResp, err := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: tampered,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should fail to decrypt if ciphertext is too short to contain nonce and tag", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("short cipher"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		// create a truncated ciphertext that is too short to contain nonce and tag
		ct := encResp.Ciphertext.SecureBytes()
		truncated, err := securemem.NewData("truncated", 8) // too short for nonce+tag
		require.NoError(t, err)

		t.Cleanup(func() { _ = truncated.Destroy() })
		copy(truncated.SecureBytes(), ct[:8])

		// when
		decResp, err := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: truncated,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should not destroy ciphertext after decryption", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Plaintext:  plainText,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		decResp, err := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: "1",
			Ciphertext: encResp.Ciphertext,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = decResp.Plaintext.Destroy() })

		// then
		assert.NotNil(t, encResp.Ciphertext.SecureBytes())
	})
}

func TestStaticSecret_Info(t *testing.T) {
	// given
	subj, err := staticsecret.New("test-static-secret", newSecretKey(t))
	require.NoError(t, err)

	// when
	info := subj.Info()

	// then
	assert.Equal(t, "test-static-secret", info.Name)
	assert.Equal(t, staticsecret.TypeStaticSecret, info.Type)
	assert.False(t, info.DecryptionSecretRequired)
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
