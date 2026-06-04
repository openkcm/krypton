package cryptor_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openkcm/krypton/internal/cryptor"
	"github.com/openkcm/krypton/internal/securemem"
)

func TestAES256GCM_Encrypt(t *testing.T) {
	// given
	ctx := t.Context()
	subj := cryptor.NewAES256GCM()

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

	t.Run("should fail if encryption secret is missing", func(t *testing.T) {
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
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail to encrypt if plaintext data is destroyed", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))
		secret := newSecretKey(t)

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  plainText,
			Secret:     secret,
		}

		// destroy plaintext before encryption
		require.NoError(t, plainText.Destroy())

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail if secret key size is invalid", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))

		// invalid secret size (should be 32 bytes for AES-256)
		secret, err := securemem.NewData("key", 16)
		require.NoError(t, err)
		t.Cleanup(func() { _ = secret.Destroy() })

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  plainText,
			Secret:     secret, // invalid key size
		}

		// when
		resp, err := subj.Encrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should generate different ciphertext for same plaintext and key", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))
		secret := newSecretKey(t)

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  plainText,
			Secret:     secret,
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

	t.Run("should not destroy secret and plaintext after encryption", func(t *testing.T) {
		// given
		plainText := newSecureMemData(t, []byte("plaintext"))
		secret := newSecretKey(t)

		req := cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Plaintext:  plainText,
			Secret:     secret,
		}

		// when
		resp, err := subj.Encrypt(ctx, req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Ciphertext.Destroy() })

		// then
		assert.NotNil(t, plainText.SecureBytes())
		assert.NotNil(t, secret.SecureBytes())
	})
}

func TestAES256GCM_Decrypt(t *testing.T) {
	// given
	ctx := t.Context()
	subj := cryptor.NewAES256GCM()

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

	t.Run("should fail if decrypt request secret is missing", func(t *testing.T) {
		// given
		cipherText := newSecureMemData(t, []byte("ciphertext"))

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Ciphertext: cipherText,
			Secret:     nil, // missing secret
		}

		// when
		resp, err := subj.Decrypt(ctx, req)

		// then
		assert.Error(t, err)
		assert.Nil(t, resp)
	})

	t.Run("should fail if secret key size is invalid", func(t *testing.T) {
		// given
		cipherText := newSecureMemData(t, []byte("ciphertext"))

		// invalid secret size (should be 32 bytes for AES-256)
		secret, err := securemem.NewData("key", 16)
		require.NoError(t, err)
		t.Cleanup(func() { _ = secret.Destroy() })

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Ciphertext: cipherText,
			Secret:     secret, // invalid key size
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
		secret := newSecretKey(t)

		req := cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Ciphertext: cipherText,
			Secret:     secret,
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

func TestAES256GCM_EncryptDecrypt(t *testing.T) {
	// given
	ctx := t.Context()
	subj := cryptor.NewAES256GCM()

	t.Run("should encrypt and decrypt plaintext successfully", func(t *testing.T) {
		// given
		secret := newSecretKey(t)
		text := []byte("hello, secure world!")
		plainText := newSecureMemData(t, text)

		// when
		// encrypt
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Secret:     secret,
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
			Secret:     secret,
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
		secret := newSecretKey(t)
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
			Secret:     secret,
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
			Secret:     secret,
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
		secretKey := newSecretKey(t)
		plainText := newSecureMemData(t, []byte("secret"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Secret:     secretKey,
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
			Secret:     secretKey,
			Ciphertext: encResp.Ciphertext,
			AAD:        []byte("wrong-aad"),
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should fail to decrypt with wrong key", func(t *testing.T) {
		// given
		secret1 := newSecretKey(t)
		secret2 := newSecretKey(t)
		plainText := newSecureMemData(t, []byte("secret"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Secret:     secret1,
			Plaintext:  plainText,
		})

		// then
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		// when
		// decrypt with different key must fail
		decResp, err := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Secret:     secret2,
			Ciphertext: encResp.Ciphertext,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should fail to decrypt tampered ciphertext", func(t *testing.T) {
		// given
		secret := newSecretKey(t)
		plaintText := newSecureMemData(t, []byte("do not tamper"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Secret:     secret,
			Plaintext:  plaintText,
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
			Secret:     secret,
			Ciphertext: tampered,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should fail to decrypt if cipher is too short to contain nonce and tag", func(t *testing.T) {
		// given
		secret := newSecretKey(t)
		plainText := newSecureMemData(t, []byte("short cipher"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Secret:     secret,
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
			Secret:     secret,
			Ciphertext: truncated,
		})

		// then
		assert.Error(t, err)
		assert.Nil(t, decResp)
	})

	t.Run("should not destroy secret and ciphertext after decryption attempt", func(t *testing.T) {
		// given
		secret := newSecretKey(t)
		plainText := newSecureMemData(t, []byte("plaintext"))

		// when
		encResp, err := subj.Encrypt(ctx, cryptor.EncryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Secret:     secret,
			Plaintext:  plainText,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = encResp.Ciphertext.Destroy() })

		decResp, _ := subj.Decrypt(ctx, cryptor.DecryptRequest{
			TenantID:   "tenant-1",
			KeyID:      "key-1",
			KeyVersion: 1,
			Algorithm:  cryptor.KeyAlgorithmAES256,
			Secret:     secret,
			Ciphertext: encResp.Ciphertext,
		})

		t.Cleanup(func() { _ = decResp.Plaintext.Destroy() })

		// then
		assert.NotNil(t, secret.SecureBytes())
		assert.NotNil(t, encResp.Ciphertext.SecureBytes())
	})
}

func TestAES256GCM_Info(t *testing.T) {
	// given
	subj := cryptor.NewAES256GCM()

	// when
	info := subj.Info()

	// then
	assert.Equal(t, cryptor.InfoNameAES256GCM, info.Name)
	assert.True(t, info.DecryptionSecretRequired)
}
