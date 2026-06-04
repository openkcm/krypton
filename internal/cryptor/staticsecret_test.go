package cryptor_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
)

func TestStaticSecretNew(t *testing.T) {
	// given
	tts := []struct {
		name    string
		nameArg cryptor.InfoName
		keyArg  *securemem.Data
		wantErr bool
	}{
		{
			name:    "should not return error for valid name and key",
			nameArg: cryptor.InfoNameStaticSecret,
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
			nameArg: cryptor.InfoNameStaticSecret,
			keyArg:  nil,
			wantErr: true,
		},
		{
			name:    "should return error for empty secret",
			nameArg: cryptor.InfoNameStaticSecret,
			keyArg:  &securemem.Data{},
			wantErr: true,
		},
		{
			name:    "should return error if name is unknown",
			nameArg: "unknown-name",
			keyArg:  newSecretKey(t),
			wantErr: true,
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			// when
			subj, err := cryptor.NewStaticSecret(tt.nameArg, tt.keyArg)

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

func TestStaticSecretEncrypt(t *testing.T) {
	// given
	ctx := t.Context()

	subj, err := cryptor.NewStaticSecret(cryptor.InfoNameStaticSecret, newSecretKey(t))
	require.NoError(t, err)

	t.Run("should fail if encrypt request validation fails", func(t *testing.T) {
		// given
		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  nil, // missing plaintext
		}

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail if request contains secret", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  plainText,
			Secret:     newSecretKey(t),
		}

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should not fail if encryption secret is missing", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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

	t.Run("should fail if algorithm is unknown", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  "unknown-algorithm",
			Plaintext:  plainText,
			Secret:     nil, // missing secret
		}

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail to encrypt if plaintext data is destroyed", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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

func TestStaticSecretDecrypt(t *testing.T) {
	// given
	ctx := t.Context()
	subj, err := cryptor.NewStaticSecret(cryptor.InfoNameStaticSecret, newSecretKey(t))
	require.NoError(t, err)

	t.Run("should fail if decrypt request validation fails", func(t *testing.T) {
		// given
		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Ciphertext: nil, // missing ciphertext
		}

		// when
		resp, err := subj.Decrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail if decrypt request secret is present", func(t *testing.T) {
		// given
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  newSecureMemData(t, []byte("ciphertext")),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Ciphertext: encResp.Ciphertext,
			Secret:     newSecretKey(t),
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  newSecureMemData(t, []byte("ciphertext")),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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

	t.Run("should fail if algorithm is unknown", func(t *testing.T) {
		// given
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  newSecureMemData(t, []byte("ciphertext")),
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  "unknown-algorithm",
			Ciphertext: encResp.Ciphertext,
		}

		// when
		resp, err := subj.Decrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail to decrypt if ciphertext data is destroyed", func(t *testing.T) {
		// given
		cipherText := newSecureMemData(t, []byte("ciphertext"))

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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

func TestStaticSecretEncryptDecrypt(t *testing.T) {
	// given
	ctx := t.Context()

	subj, err := cryptor.NewStaticSecret(cryptor.InfoNameStaticSecret, newSecretKey(t))
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		// when
		// decrypt with different staticsecret must fail
		subj1, err := cryptor.NewStaticSecret(cryptor.InfoNameStaticSecret, newSecretKey(t))
		require.NoError(t, err)

		decResp, err := subj1.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Ciphertext: tampered,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should fail to decrypt if cipher is too short to contain nonce and tag", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("short cipher"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
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
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Ciphertext: truncated,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should not destroy ciphertext after decryption attempt", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  plainText,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		decResp, _ := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Ciphertext: encResp.Ciphertext,
		})

		t.Cleanup(func() { _ = decResp.Plaintext.Destroy() })

		// then
		assert.NotNil(t, encResp.Ciphertext.SecureBytes())
	})
}

func TestStaticSecretInfo(t *testing.T) {
	// given
	subj, err := cryptor.NewStaticSecret(cryptor.InfoNameStaticSecret, newSecretKey(t))
	require.NoError(t, err)

	// when
	info := subj.Info()

	// then
	assert.Equal(t, cryptor.InfoNameStaticSecret, info.Name)
	assert.False(t, info.DecryptionSecretRequired)
}
